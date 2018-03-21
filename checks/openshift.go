package checks

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"time"
	"io/ioutil"
	"path/filepath"
	"encoding/pem"
	"crypto/x509"
	"gopkg.in/yaml.v2"
	"encoding/base64"
)

func CheckMasterApis(urls string) error {
	log.Println("Checking master apis. At least one has to be up")

	urlArr := strings.Split(urls, ",")

	oneApiOk := false
	var msg string
	for _, u := range urlArr {
		if err := checkHttp(u); err == nil {
			oneApiOk = true
		} else {
			msg += u + " is not reachable. "
		}
	}

	if oneApiOk {
		return nil
	} else {
		return errors.New(msg)
	}
}

func CheckOcGetNodes() error {
	log.Println("Checking oc get nodes output")

	out, err := runOcGetNodes()
	if err != nil {
		return err
	}

	if strings.Contains(out, "NotReady") {
		// Wait a few seconds and see if still NotReady
		// to avoid wrong alerts
		time.Sleep(10 * time.Second)

		out2, err := runOcGetNodes()
		if err != nil {
			return err
		}
		if strings.Contains(out2, "NotReady") {
			return errors.New("Some node is not ready! 'oc get nodes' output contained NotReady. Output: " + out2)
		}
	}

	return nil
}

func runOcGetNodes() (string, error) {
	out, err := exec.Command("bash", "-c", "oc get nodes --show-labels | grep -v monitoring=false | grep -v SchedulingDisabled").Output()
	if err != nil {
		msg := "Could not parse oc get nodes output: " + err.Error()
		log.Println(msg)
		return "", errors.New(msg)
	}
	return string(out), nil
}

func CheckDnsNslookupOnKubernetes() error {
	log.Println("Checking nslookup to kubernetes ip")

	cmd := exec.Command("nslookup", daemonDNSEndpoint, kubernetesIP)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		msg := "DNS resolution via nslookup & kubernetes failed." + err.Error()
		log.Println(msg)
		return errors.New(msg)
	}

	stdOut := out.String()

	if strings.Contains(stdOut, "Server") && strings.Count(stdOut, "Address") >= 2 && strings.Contains(stdOut, "Name") {
		return nil
	} else {
		return errors.New("Problem with dns to kubernetes. nsLookup had wrong output")
	}
}

func CheckDnsServiceNode() error {
	log.Println("Checking dns to a openshift service")

	ips := getIpsForName(daemonDNSServiceA)

	if ips == nil {
		return errors.New("Failed to lookup ip on node (dnsmasq) for name " + daemonDNSServiceA)
	} else {
		return nil
	}
}

func CheckDnsInPod() error {
	log.Println("Checking dns to a openshift service inside a pod")

	ips := getIpsForName(daemonDNSPod)

	if ips == nil {
		return errors.New("Failed to lookup ip in pod for name " + daemonDNSPod)
	} else {
		return nil
	}
}

func CheckPodHttpAtoB() error {
	log.Println("Checking if http connection does not work if network not joined")

	// This should fail as we do not have access to this project
	if err := checkHttp("http://" + daemonDNSServiceB + ":8090/hello"); err == nil {
		errors.New("Pod A could access pod b. This should not be allowed!")
	}

	return nil
}

func CheckPodHttpAtoC(slow bool) error {
	log.Println("Checking if http connection does work with joined network")

	if err := checkHttp("http://" + daemonDNSServiceC + ":8090/" + getEndpoint(slow)); err != nil {
		return errors.New("Pod A could access pod C. This should not work. Route/Router problem?")
	}

	return nil
}

func CheckHttpService(slow bool) error {
	errA := checkHttp("http://" + daemonDNSServiceA + ":8090/" + getEndpoint(slow))
	errB := checkHttp("http://" + daemonDNSServiceB + ":8090/" + getEndpoint(slow))
	errC := checkHttp("http://" + daemonDNSServiceC + ":8090/" + getEndpoint(slow))

	if errA != nil || errB != nil || errC != nil {
		msg := "Could not reach one of the services (a/b/c)"
		log.Println(msg)
		return errors.New(msg)
	}

	return nil
}

func CheckHttpHaProxy(publicUrl string, slow bool) error {
	log.Println("Checking http via HA-Proxy")

	if err := checkHttp(publicUrl + ":80/" + getEndpoint(slow)); err != nil {
		return errors.New("Could not access pods via haproxy. Route/Router problem?")
	}

	return nil
}

func CheckRegistryHealth(ip string) error {
	log.Println("Checking registry health")

	if err := checkHttp("http://" + ip + ":5000/healthz"); err != nil {
		return fmt.Errorf("Registry health check failed. %v", err.Error())
	}

	return nil
}

func CheckHawcularHealth(ip string) error {
	log.Println("Checking metrics health")

	if err := checkHttp("https://" + ip + ":443"); err != nil {
		return errors.New("Hawcular health check failed")
	}

	return nil
}

func CheckRouterHealth(ip string) error {
	log.Println("Checking router health", ip)

	if err := checkHttp("http://" + ip + ":1936/healthz"); err != nil {
		return fmt.Errorf("Router health check failed for %v, %v", ip, err.Error())
	}

	return nil
}

func CheckLoggingRestartsCount() error {
	log.Println("Checking log-container restart count")

	out, err := exec.Command("bash", "-c", "oc get pods -n logging -o wide | tr -s ' ' | cut -d ' ' -f 4").Output()
	if err != nil {
		msg := "Could not parse logging container restart count: " + err.Error()
		log.Println(msg)
		return errors.New(msg)
	}

	isOk := true
	var msg string
	for _, l := range strings.Split(string(out), "\n") {
		if !strings.HasPrefix(l, "RESTARTS") && len(strings.TrimSpace(l)) > 0 {
			cnt, _ := strconv.Atoi(l)
			if cnt > 2 {
				msg = "A logging-container has restart count bigger than 2 - " + strconv.Itoa(cnt)
				isOk = false
			}
		}
	}

	if !isOk {
		return errors.New(msg)
	} else {
		return nil
	}
}

func CheckRouterRestartCount() error {
	log.Println("Checking router restart count")

	out, err := exec.Command("bash", "-c", "oc get po -n default | grep router | grep -v deploy | tr -s ' ' | cut -d ' ' -f 4").Output()
	if err != nil {
		msg := "Could not parse router restart count: " + err.Error()
		log.Println(msg)
		return errors.New(msg)
	}

	isOk := true
	var msg string
	for _, l := range strings.Split(string(out), "\n") {
		if !strings.HasPrefix(l, "RESTARTS") && len(strings.TrimSpace(l)) > 0 {
			cnt, _ := strconv.Atoi(l)
			if cnt > 5 {
				msg = "A Router has restart count bigger than 5 - " + strconv.Itoa(cnt)
				isOk = false
			}
		}
	}

	if isOk {
		return nil
	} else {
		return errors.New(msg)
	}
}

func CheckEtcdHealth(etcdIps string, etcdCertPath string) error {
	log.Println("Checking etcd health")

	var msg string
	isOk := true

	if len(etcdCertPath) > 0 {
		// Check etcd with custom certs path
		isOk = checkEtcdHealthWithCertPath(&msg, etcdCertPath, etcdIps)

		if !isOk {
			log.Println("etcd health check with custom cert path failed, trying with default")

			// Check etcd with default certs path
			isOk = checkEtcdHealthWithCertPath(&msg, "/etc/etcd/", etcdIps)
		}
	} else {
		// Check etcd with default certs path
		isOk = checkEtcdHealthWithCertPath(&msg, "/etc/etcd/", etcdIps)
	}

	if !isOk {
		return errors.New(msg)
	} else {
		return nil
	}
}

func checkEtcdHealthWithCertPath(msg *string, certPath string, etcdIps string) bool {
	cmd := exec.Command("etcdctl", "--peers", etcdIps, "--ca-file", certPath+"ca.crt",
		"--key-file", certPath+"peer.key", "--cert-file", certPath+"peer.crt", "cluster-health")

	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Println("error while running etcd health check", err)
		*msg = "etcd health check failed: " + err.Error()
		return false
	}

	stdOut := out.String()
	if strings.Contains(stdOut, "unhealthy") || strings.Contains(stdOut, "unreachable") {
		*msg += "Etcd health check was 'cluster unhealthy'"
		return false
	}

	return true
}

func CheckLimitsAndQuotas(allowedWithout int) error {
	log.Println("Checking limits & quotas")

	// Count projects
	projectCount, err := exec.Command("bash", "-c", "oc get projects  | wc -l").Output()
	if err != nil {
		msg := "Could not parse project count" + err.Error()
		log.Println(msg)
		return errors.New(msg)
	}

	// Count limits
	limitCount, err := exec.Command("bash", "-c", "oc get limits --all-namespaces | wc -l").Output()
	if err != nil {
		msg := "Could not parse limit count" + err.Error()
		log.Println(msg)
		return errors.New(msg)
	}

	// Count quotas
	quotaCount, err := exec.Command("bash", "-c", "oc get quota --all-namespaces | wc -l").Output()
	if err != nil {
		msg := "Could not parse quota count" + err.Error()
		log.Println(msg)
		return errors.New(msg)
	}

	// Parse them
	pCount, err := strconv.Atoi(strings.TrimSpace(string(projectCount)))
	lCount, _ := strconv.Atoi(strings.TrimSpace(string(limitCount)))
	qCount, _ := strconv.Atoi(strings.TrimSpace(string(quotaCount)))

	log.Println("Parsed values (projects,limits,quotas)", pCount, lCount, qCount)

	if pCount-allowedWithout != lCount {
		return errors.New("There are some projects without limits")
	}
	if pCount-allowedWithout != qCount {
		return errors.New("There are some projects without quotas")
	}

	return nil
}

func decodeCertBlocks(data []byte) []*pem.Block  {
	var blocks []*pem.Block
	block, rest := pem.Decode([]byte(data))

	if block != nil {
		blocks = append(blocks, block)
	}

	if len(rest) > 0 {
		return append(blocks, decodeCertBlocks(rest)...)
	} else {
		return blocks
	}
}

type KubeConfig struct {
	APIVersion string `yaml:"apiVersion"`
	Clusters   []struct {
		Cluster struct {
			CertificateAuthorityData string `yaml:"certificate-authority-data"`
			Server                   string `yaml:"server"`
		} `yaml:"cluster"`
		Name string `yaml:"name"`
	} `yaml:"clusters"`
	Contexts []struct {
		Context struct {
			Cluster   string `yaml:"cluster"`
			Namespace string `yaml:"namespace"`
			User      string `yaml:"user"`
		} `yaml:"context"`
		Name string `yaml:"name"`
	} `yaml:"contexts"`
	CurrentContext string `yaml:"current-context"`
	Kind           string `yaml:"kind"`
	Preferences    struct {
	} `yaml:"preferences"`
	Users []struct {
		Name string `yaml:"name"`
		User struct {
			ClientCertificateData string `yaml:"client-certificate-data"`
			ClientKeyData         string `yaml:"client-key-data"`
		} `yaml:"user"`
	} `yaml:"users"`
}

func CheckSslCertificates(filePaths []string, days int) error {
	log.Println("Checking expiry date for SSL certificates (" + strconv.Itoa(days) + " days).")

	var certFiles []string

	for _, path := range filePaths {
		log.Println("Checking path", path + ".")
		files, err := ioutil.ReadDir(path)
		if err != nil {
			msg := "could not read directory " + path + " (" + err.Error() + ")"
			log.Println(msg)
			return errors.New(msg)
		}

		for _, file := range files {
			if file.IsDir() || filepath.Ext(file.Name()) != ".crt" {
				continue
			}

			certFiles = append(certFiles, filepath.Join(path, file.Name()))
		}
	}

	var certErrorList []string

	for _, file := range certFiles {

		data, err := ioutil.ReadFile(file)
		if err != nil {
			msg := "could not read file " + file
			log.Println(msg)
			return errors.New(msg)
		}

		blocks := decodeCertBlocks([]byte(data))

		for _, block := range blocks {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				msg := "certificate parsing error (" + err.Error() + ")"
				log.Println(msg)
				return errors.New(msg)
			}

			daysLeft := cert.NotAfter.Sub(time.Now()).Hours()/24

			if int(daysLeft) <= days {
				msg := file + " expires in " + strconv.Itoa(int(daysLeft)) + " days"
				log.Println(msg)
				certErrorList = append(certErrorList, msg)
			} else {
				log.Println(file + " expires in " + strconv.Itoa(int(daysLeft)) + " days. This is OK.")
			}
		}

	}

	data, err := ioutil.ReadFile("/root/.kube/config")
	if err != nil {
		msg := "could not read file /root/.kube/config"
		log.Println(msg)
		return errors.New(msg)
	}

	var kubeConfig KubeConfig

	err = yaml.Unmarshal(data, &kubeConfig)
	if err != nil {
		msg := "unmarhsalling /root/.kube/config failed (" + err.Error() + ")"
		log.Println(msg)
		return errors.New(msg)
	}

	for _, cluster := range kubeConfig.Clusters {
		if len(cluster.Cluster.CertificateAuthorityData) > 0 {

			certBytes, _ := base64.StdEncoding.DecodeString(cluster.Cluster.CertificateAuthorityData)
			block, _ := pem.Decode(certBytes)

			cert, err := x509.ParseCertificate(block.Bytes)

			if err != nil {
				msg := "certificate parsing error (" + err.Error() + ")"
				log.Println(msg)
				return errors.New(msg)
			}

			daysLeft := cert.NotAfter.Sub(time.Now()).Hours()/24

			if int(daysLeft) <= days {
				msg := "certificate-authority-data from /root/.kube/config expires in " + strconv.Itoa(int(daysLeft)) + " days"
				log.Println(msg)
				certErrorList = append(certErrorList, msg)
			} else {
				log.Println("certificate-authority-data from /root/.kube/config expires in " + strconv.Itoa(int(daysLeft)) + " days. This is OK.")
			}
		}
	}

	for _, user := range kubeConfig.Users {
		if len(user.User.ClientCertificateData) > 0 {

			certBytes, _ := base64.StdEncoding.DecodeString(user.User.ClientCertificateData)
			block, _ := pem.Decode(certBytes)

			cert, err := x509.ParseCertificate(block.Bytes)

			if err != nil {
				msg := "certificate parsing error (" + err.Error() + ")"
				log.Println(msg)
				return errors.New(msg)
			}

			daysLeft := cert.NotAfter.Sub(time.Now()).Hours()/24

			if int(daysLeft) <= days {
				msg := "client-certificate-data from /root/.kube/config expires in " + strconv.Itoa(int(daysLeft)) + " days"
				log.Println(msg)
				certErrorList = append(certErrorList, msg)
			} else {
				log.Println("client-certificate-data from /root/.kube/config expires in " + strconv.Itoa(int(daysLeft)) + " days. This is OK.")
			}
		}
	}

	if len(certErrorList) > 0 {
		var errorMessage string
		for _, msg := range certErrorList {
			errorMessage = errorMessage + msg + " "
		}
		return errors.New(errorMessage)
	}

	return nil
}
