package k8s

import (
	"context"
	"eDNS/config"
	"sync"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

type NetAddress struct {
	Host string `yaml:"Host"`
	IP   string `yaml:"IP"`
	Type string `yaml:"Type"`
	Svc  string `yaml:"Svc"`
	NS   string `yaml:"NS"`
}

type Watcher struct {
	client        kubernetes.Interface
	ServiceCtrl   *ServiceCtroller
	ServiceAdd    chan NetAddress
	ServiceRemove chan NetAddress
	readyCount    int32
	onFinish      func()
}

func NewWatcher(c *config.Configuration, onChange func()) *Watcher {
	var config = &rest.Config{}
	var err error

	w := &Watcher{
		onFinish: onChange,
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

	w.ServiceAdd = make(chan NetAddress, 10)
	w.ServiceRemove = make(chan NetAddress, 10)

	return w
}

func (w *Watcher) Run() {

	if w.client == nil {

		w.onFinish()
		return
	}

	var svcOnce sync.Once

	factory := informers.NewSharedInformerFactory(w.client, time.Hour)

	onServiceChange := func(svc *corev1.Service, isDelete bool) {
		svcOnce.Do(func() { w.onChanged() })
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
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		inf := factory.Core().V1().Services().Informer()
		inf.AddEventHandler(serviceHandler)
		inf.Run(context.TODO().Done())
		wg.Done()
	}()

	wg.Wait()
}

func (w *Watcher) onChanged() {
	atomic.AddInt32(&w.readyCount, 1)
	if w.readyCount == 1 {
		w.onFinish()
	}
}
