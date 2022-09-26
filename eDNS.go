package main

import (
	"eDNS/k8s"
	"eDNS/kernel"
	"eDNS/modules"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
)

func main() {

	// 环境检测
	// 系统内核版本检测
	kv, err := kernel.HostVersion()
	if err != nil {
		log.Fatal(err)
	}
	if kv < kernel.VersionCode(4, 15, 0) {
		log.Fatalf("Linux Kernel version %v is not supported. Need > 4.15 .", kv)
	} else {
		log.Printf("linux kernel version %v check ok!", kv)
	}

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	log.Println("eDNS start...")
	log.Printf("process pid: %d\n", os.Getpid())

	localIP, localIF := modules.GetLocalIP()
	log.Printf("local ip: %s on %s\n", localIP, localIF)

	dw, err := modules.NewWorker()
	if err != nil {
		log.Printf("Start eDNS worker error: %v", err)
	} else {
		k8sReady := make(chan bool)
		dw.K8SWatcher = k8s.NewWatcher(dw.WConfig, func() {
			once.Do(func() { k8sReady <- true })
		})
		go dw.K8SWatcher.Run()
		<-k8sReady

		dw.Run()

	}

	// wd, err := modules.NewWorkerDispatch()
	// if err != nil {
	// 	log.Printf("Start dispatch error: %v", err)
	// } else {
	// 	wd.HostUname = uname
	// 	wd.InitWorkers()
	// 	wd.Run()

	// }

	<-stopper

	// wd.Stop()

	log.Println("Received signal, exiting program..")
}
