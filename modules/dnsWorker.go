package modules

import (
	"bytes"
	"eDNS/assets"
	"eDNS/config"
	"eDNS/k8s"
	"errors"
	"fmt"
	"log"
	"math"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	manager "github.com/ehids/ebpfmanager"
	"golang.org/x/sys/unix"
)

type DNSWorker struct {
	WConfig           *config.Configuration
	K8SWatcher        *k8s.Watcher
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventMap          *ebpf.Map
}

func NewWorker() (*DNSWorker, error) {
	log.Println("Read Config...")
	wConfig, err := config.NewConfig()
	if err != nil {
		return nil, err
	}
	wd := &DNSWorker{}
	wd.WConfig = wConfig
	return wd, nil
}

func (w *DNSWorker) Run() error {
	log.Println("[eDNS] begin start core")
	// fetch ebpf assets
	buf, err := assets.Asset("ebpf/bin/tc_dns.o")
	if err != nil {
		return errors.New(fmt.Sprintf("couldn't find asset %s", err))
	}
	// setup the managers
	w.setupManager()
	// initialize the bootstrap manager
	if err := w.bpfManager.InitWithOptions(bytes.NewReader(buf), w.bpfManagerOptions); err != nil {
		return errors.New(fmt.Sprintf("couldn't init manager, %s", err))
	}
	// start the bootstrap manager
	if err := w.bpfManager.Start(); err != nil {
		return errors.New("couldn't start bootstrap manager")
	}

	// err = w.setupKernelMap()
	// if err != nil {
	// 	return err
	// }

	// err = w.setupEventMap()
	// if err != nil {
	// 	return err
	// }

	// err = w.readEvents()
	// if err != nil {
	// 	return err
	// }

	return nil
}

func (w *DNSWorker) setupManager() {
	ifname := w.WConfig.Ifname
	if ifname == "" {
		_, ifname = GetLocalIP()
	}
	w.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				//show filter
				//tc filter show dev eth0 ingress(egress)
				// customize deleteed TC filter
				// tc filter del dev eth0 ingress(egress)
				UID:              "tc_dns",
				Section:          "classifier/egress",
				EbpfFuncName:     "tc_dns_func",
				Ifname:           ifname,
				NetworkDirection: manager.Egress,
			},
		},
	}

	w.bpfManagerOptions = manager.Options{
		DefaultKProbeMaxActive: 512,
		VerifierOptions: ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				LogSize:     2097152,
				KernelTypes: w.getBTFSpec(),
			},
		},
		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
	}
}

func (w *DNSWorker) getBTFSpec() *btf.Spec {
	if w.WConfig.ExtBTF == "" {
		return nil
	} else {
		spec, err := btf.LoadSpec(w.WConfig.ExtBTF)
		if err != nil {
			log.Printf("load external BTF from [%s], failed, %v", w.WConfig.ExtBTF, err)
			return nil
		} else {
			log.Printf("load external BTF from, %s", w.WConfig.ExtBTF)
			return spec
		}
	}
}
