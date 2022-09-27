package modules

import (
	"context"
	"eDNS/config"
	"fmt"
	"log"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

type (
	K8SWatcher struct {
		client        kubernetes.Interface
		ServiceCtrl   *ServiceCtroller
		ServiceChange chan NetAddress
		readyCount    int32
	}

	ServiceCtroller struct {
		sync.RWMutex
		w        *K8SWatcher
		Services map[string]*ServiceInfo
	}

	ServiceInfo struct {
		Name            string
		Namespace       string
		ResourceVersion string
		Address         []NetAddress
	}
)

func NewWatcher(c *config.Configuration, sc chan NetAddress) *K8SWatcher {
	var config = &rest.Config{}
	var err error
	w := &K8SWatcher{
		ServiceChange: sc,
	}
	w.ServiceCtrl = &ServiceCtroller{w: w, Services: make(map[string]*ServiceInfo)}
	if c.EnableK8S {
		if c.IsInK8S {
			config, err = rest.InClusterConfig()
			if err != nil {
				panic(err.Error())
			}
		} else {
			// for local test, out of k8s
			config, err = clientcmd.BuildConfigFromFlags("", "config/kube.yaml")
			if err != nil {
				panic(err.Error())
			}
		}
		client, err := kubernetes.NewForConfig(config)
		if err != nil {
			panic(err.Error())
		}
		w.client = client
	}
	return w
}

func (w *K8SWatcher) Run() {
	if w.client == nil {
		return
	}
	factory := informers.NewSharedInformerFactory(w.client, time.Hour)
	onServiceChange := func(svc *corev1.Service, isDelete bool) {
		w.ServiceCtrl.ServiceChanged(svc, isDelete)
	}
	serviceHandler := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			svc := obj.(*corev1.Service)
			onServiceChange(svc, false)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			svc := newObj.(*corev1.Service)
			onServiceChange(svc, false)
		},
		DeleteFunc: func(obj interface{}) {
			svc := obj.(*corev1.Service)
			onServiceChange(svc, true)
		},
	}
	go func() {
		inf := factory.Core().V1().Services().Informer()
		inf.AddEventHandler(serviceHandler)
		inf.Run(context.TODO().Done())
	}()
}

func (w *K8SWatcher) ServiceChanged(addr []NetAddress, isDelete bool) {
	for _, a := range addr {
		a.IsDelete = isDelete
		w.ServiceChange <- a
	}
}

func (s *ServiceCtroller) ServiceChanged(svc *corev1.Service, isDelete bool) {
	key := fmt.Sprintf("%s.%s", svc.Name, svc.Namespace)
	old, ok := s.Services[key]
	if ok && old.ResourceVersion == svc.ResourceVersion {
		return
	}

	s.Lock()
	defer s.Unlock()

	svcIP := svc.Spec.ClusterIP
	if ok {
		s.w.ServiceChanged(old.Address, true)
	}

	if isDelete {
		log.Printf("service removed: [%s.%s]\n", svc.Name, svc.Namespace)
		delete(s.Services, key)
	} else {
		newAddress := []NetAddress{}
		addr := NetAddress{
			Host: key,
			IP:   svcIP,
			Svc:  svc.Name,
			NS:   svc.Namespace,
		}
		newAddress = append(newAddress, addr)
		if !ok {
			log.Printf("service add: [%s.%s]\n", svc.Name, svc.Namespace)
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
		s.w.ServiceChanged(newAddress, false)
	}
}
