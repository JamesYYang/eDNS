package k8s

import (
	"fmt"
	"log"
	"sync"

	corev1 "k8s.io/api/core/v1"
)

type (
	ServiceCtroller struct {
		sync.RWMutex
		w        *Watcher
		Services map[string]*ServiceInfo
	}

	ServiceInfo struct {
		Name            string
		Namespace       string
		ResourceVersion string
		Address         []NetAddress
	}
)

func (s *ServiceCtroller) ServiceChanged(svc *corev1.Service, isDelete bool) {
	key := fmt.Sprintf("%s.%s", svc.Name, svc.Namespace)
	old, ok := s.Services[key]
	if ok && old.ResourceVersion == svc.ResourceVersion {
		return
	}

	s.Lock()
	defer s.Unlock()

	svcIP := svc.Spec.ClusterIP
	// if ok {
	// 	s.w.IpCtrl.RemoveEndpoint(old.Address)
	// }

	if isDelete {
		log.Printf("service removed: [%s.%s]\n", svc.Name, svc.Namespace)
		delete(s.Services, key)
	} else {
		newAddress := []NetAddress{}
		addr := NetAddress{
			Host: key,
			IP:   svcIP,
			Type: "Service",
			Svc:  svc.Name,
			NS:   svc.Namespace,
		}
		newAddress = append(newAddress, addr)
		if !ok {
			log.Printf("service add: [%s.%s]\n", svc.Name, svc.Namespace)
			// log.Printf("port info: %+v", newPorts)
			s.Services[key] = &ServiceInfo{
				Name:            svc.Name,
				Namespace:       svc.Namespace,
				ResourceVersion: svc.ResourceVersion,
				Address:         newAddress,
			}
		} else {
			log.Printf("service changed: [%s.%s]\n", svc.Name, svc.Namespace)
			old.ResourceVersion = svc.ResourceVersion
			old.Address = newAddress
		}
		// s.w.IpCtrl.AddEndpoint(newAddress)
	}
}
