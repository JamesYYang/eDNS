package modules

import (
	"bytes"
	"eDNS/assets"
	"eDNS/config"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/perf"
	manager "github.com/ehids/ebpfmanager"
	"golang.org/x/sys/unix"
)

type DNSWorker struct {
	WConfig           *config.Configuration
	dp                *DomainProvider
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventMap          *ebpf.Map
	dnsMap            *ebpf.Map
}

func NewWorker() (*DNSWorker, error) {
	log.Println("Read Config...")
	wConfig, err := config.NewConfig()
	if err != nil {
		return nil, err
	}
	wd := &DNSWorker{}
	wd.WConfig = wConfig
	wd.dp = NewDomainProvider(wConfig)
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

	err = w.setupKernelMap()
	if err != nil {
		return err
	}

	err = w.setupEventMap()
	if err != nil {
		return err
	}

	w.dp.LoadDomain()

	err = w.readEvents()
	if err != nil {
		return err
	}

	return nil
}

func (w *DNSWorker) setupManager() {
	ifname := w.WConfig.Ifname
	if ifname == "" {
		_, ifname = GetLocalIP()
	}
	log.Printf("attach tc hook on dev: %s", ifname)
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

func (w *DNSWorker) setupKernelMap() error {
	em, found, err := w.bpfManager.GetMap("dns_a_records")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map: dns_a_records")
	}
	w.dnsMap = em

	go func(sc chan NetAddress) {
		for {
			select {
			case na := <-sc:
				w.UpdateDNSMap(na)
			}
		}
	}(w.dp.ServiceChange)

	return nil
}

func (w *DNSWorker) UpdateDNSMap(addr NetAddress) {
	qk := getKey(addr.Host)
	if addr.IsDelete {
		log.Printf("remove DNS[%s]", addr.Host)
		err := w.dnsMap.Delete(qk)
		if err != nil {
			log.Printf("Remove DNS[%s] map failed, error: %v", addr.Host, err)
		}
	} else {
		ip := net.ParseIP(addr.IP)
		if ip == nil {
			log.Printf("Parse DNS[%s] IP[%s] failed", addr.Host, addr.IP)
			return
		}
		record := DNSRecord{
			IP:  binary.LittleEndian.Uint32(ip.To4()),
			TTL: 30,
		}
		log.Printf("Add DNS[%s] IP[%s]", addr.Host, addr.IP)
		err := w.dnsMap.Put(unsafe.Pointer(&qk), unsafe.Pointer(&record))
		if err != nil {
			log.Printf("Add DNS[%s] map failed, error: %v", addr.Host, err)
		}
	}
}

func getKey(host string) DNSQuery {
	queryKey := DNSQuery{
		RecordType: 1,
		Class:      1,
	}
	nameSlice := make([]byte, 256)
	copy(nameSlice, []byte(host))
	dnsName := replace_dots_with_length_octets(nameSlice)
	copy(queryKey.Name[:], dnsName)
	return queryKey
}

func (w *DNSWorker) setupEventMap() error {

	em, found, err := w.bpfManager.GetMap("dns_capture_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found event map: dns_capture_events")
	}
	w.eventMap = em
	return nil
}

func (w *DNSWorker) readEvents() error {
	var errChan = make(chan error, 8)
	event := w.eventMap
	log.Println("begin read events")
	go w.perfEventReader(errChan, event)

	for {
		select {
		case err := <-errChan:
			return err
		}
	}
}

func (w *DNSWorker) perfEventReader(errChan chan error, em *ebpf.Map) {
	log.Println("begin to read from perfbuf")
	rd, err := perf.NewReader(em, os.Getpagesize())
	if err != nil {
		errChan <- fmt.Errorf("creating %s reader dns: %s", em.String(), err)
		return
	}
	defer rd.Close()
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			errChan <- fmt.Errorf("reading from perf event reader: %s", err)
			return
		}

		if record.LostSamples != 0 {
			log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}

		w.Decode(record.RawSample)
	}
}

func (w *DNSWorker) Decode(b []byte) {
	var event Net_DNS_Event
	if err := binary.Read(bytes.NewBuffer(b), binary.LittleEndian, &event); err != nil {
		return
	}

	strMsg := fmt.Sprintf("[DNS] [%s] (Type: %d, Match: %d, Spend: %d)",
		unix.ByteSliceToString(replace_length_octets_with_dots(event.Name[:])),
		event.RecordType, event.IsMatch, event.TS)

	log.Println(strMsg)
}

func (w *DNSWorker) Stop() {
	log.Println("stopping DNS worker")
	err := w.bpfManager.Stop(manager.CleanAll)
	if err != nil {
		log.Printf("stop DNS worker failed, error: %v", err)
	}
}
