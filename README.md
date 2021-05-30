# Container runtime security monitoring with Falco and Redhat Openshift

## Why we need?

Containers running in production environments actively fulfill requests from the internet or internal microservices, and are the constant subject of scans, attacks, and data exfiltration attempts by malicious actors. Considering the dynamic nature of container environments – and many container, host, and network surfaces which may come under attack – best practices like vulnerability scanning and hardening attack surfaces are simply not enough to achieve the complete runtime protection now required.

## Falco as the tool

Falco is a cloud-native runtime security system that works with both containers and raw Linux hosts. It was developed by Sysdig and is an incubating project in the Cloud Native Computing Foundation. Falco works by looking at file changes, network activity, the process table, and other data for suspicious behavior and then sending alerts through a pluggable back end. It inspects events at the system call level of a host through a kernel module or an extended BPF probe. Falco contains a rich set of rules that you can edit for flagging specific abnormal behaviors and for creating allow lists for normal computer operations.

Falco as a tool has 3 components:
1. Falco - the core framework where policy rules are configured into
2. Falco Sidekick - a daemon that extends a number of possible outputs from Falco and respective integration
3. Falo Sidekick UI - a simple web UI where all those container security events are displayed in a dashboard.

While in this example, we are using Sidekick UI as the output, but looking at the available options for Sidekick, one can easily integrate from Slack, Pagerduty, Prometheus to any public cloud event sourcing resources like Azure Event Hub or AWS Lamda.

## View a Falco rule

Falco rules, which governs, how it will treat any activity in the container, is configured at:

`https://github.com/falcosecurity/charts/tree/master/falco/rules`

A sample rule like below watches for potentially nefarious Netcat commands and throws alerts when it sees them at the WARNING level.

```bash
$ cat rules/falco_rules.yaml | grep -A 12 'Netcat Remote'
- rule: Netcat Remote Code Execution in Container
  desc: Netcat Program runs inside container that allows remote code execution
  condition: >
    spawned_process and container and
    ((proc.name = "nc" and (proc.args contains "-e" or proc.args contains "-c")) or
     (proc.name = "ncat" and (proc.args contains "--sh-exec" or proc.args contains "--exec"))
    )
  output: >
    Netcat runs inside container that allows remote code execution (user=%user.name
    command=%proc.cmdline container_id=%container.id container_name=%container.name image=%container.image.repository:%container.image.tag)
  priority: WARNING
  tags: [network, process]
```

## Prerequisites

1. Redhat OC cluster and necessary access
2. Falco (https://github.com/falcosecurity/)

## Installation

### Step 1: Create a namespace in OCP cluster

- Sign in to the OCP cluster
- Create a new namespace 'falco' with `oc create namespace falco`
- Set the new project with `oc project falco`

### Step 2: Install Falco with Helm

- add the falcosecurity charts repository with 

```bash
>helm repo add falcosecurity https://falcosecurity.github.io/charts
>helm repo update
```

NOTE: One can also download the Falco repo locally and deploy using YAML. However with Helm, it's ensured that we take the latest available deployment options

- install Falco with Sidekick and Ui enabled

```bash
>helm install falco falcosecurity/falco --set falco.docker.enabled=false --set falco.jsonOutput=true --set falcosidekick.enabled=true --set falcosidekick.webui.enabled=true -n falco
```

The output will look like:

```bash
I0529 23:46:35.524178   15776 request.go:655] Throttling request took 1.1329738s, request: GET:https://c100-e.eu-de.containers.cloud.ibm.com:32592/apis/app.k8s.io/v1beta1?timeout=32s
NAME: falco
LAST DEPLOYED: Sat May 29 23:46:37 2021
NAMESPACE: falco
STATUS: deployed
REVISION: 1
NOTES:
Falco agents are spinning up on each node in your cluster. After a few
seconds, they are going to start monitoring your containers looking for
se>curity issues.

No further action should be required.
```

NOTE:
1. we have set `falco.docker.enabled=false` as OC uses `containerd`
2. we have set `falco.jsonOutput=true` for better output representation in the Faclo event logs
3. we are simulatenously installing Sidekick and Ui so both options are set to true at installation time

### Step 3: Verify in the OC cluster

#### First, lets check how many pods were created:

```bash
oc get pods
NAME                                      READY     STATUS    RESTARTS   AGE
falco-8lvvb                               1/1       Running   0          69m
falco-9v79g                               1/1       Running   0          69m
falco-falcosidekick-669dd7b9bf-crpgz      1/1       Running   0          69m
falco-falcosidekick-669dd7b9bf-l87fc      1/1       Running   0          69m
falco-falcosidekick-ui-7fd67f6bff-wg62f   1/1       Running   0          27m
falco-qxqgw                               1/1       Running   0          69m 
```
Based upon the Helm chart specification, we have:
- 3 pods for Falco
- 2 pods for Falco Sidekick
- 1 pod for Falco Sidekick-UI

#### ALERT!
In case you find all of the above are not created, then check the `Deployment` pane and check if you find an error like this:

- for Sidekick

```bash
pods "falco-falcosidekick-669dd7b9bf-" is forbidden: unable to validate against any security context constraint: [fsGroup: Invalid value: []int64{1234}: 1234 is not an allowed group spec.containers[0].securityContext.securityContext.runAsUser: Invalid value: 1234: must be in the ranges: [1001020000, 1001029999]]
```
- for Sidekick-UI

```bash
pods "falco-falcosidekick-ui-7fd67f6bff-" is forbidden: unable to validate against any security context constraint: [fsGroup: Invalid value: []int64{1234}: 1234 is not an allowed group spec.containers[0].securityContext.securityContext.runAsUser: Invalid value: 1234: must be in the ranges: [1001020000, 1001029999]]
```
This happens because in Openshift, the service accounts which get created during installation, should have OpenShift Security Context Constraints set as priviledged

#### Now we check how many service accounts were created.

```bash
>oc get serviceaccount
NAME                  SECRETS   AGE
builder               2         38m
default               2         38m
deployer              2         38m
falco                 2         37m
falco-falcosidekick   2         37m
pipeline              2         38m
```

So we will have to assign both service accounts `falco` and `falco-falcosidekick` as priviledged

```bash
  >oc adm policy add-scc-to-user privileged -z falco
scc "privileged" added to: ["system:serviceaccount:falco:falco"]

  >oc adm policy add-scc-to-user privileged -z falco-falcosidekick
scc "privileged" added to: ["system:serviceaccount:falco:falco-falcosidekick"]
```
With the above, we should see the errors for Falco-Sidekick in the `Deployment` pane resolve and respective pods for Falco-Sidekick should come up.

If we still see the same error in Falco-Sidekick-UI in the `Deployment` pane, then additionally we will have to set Security Context to the `default` service account under `Falco` namespace.

```bash
  >oc adm policy add-scc-to-user privileged -z default
scc "privileged" added to: ["system:serviceaccount:falco:default"]
```
Post this, we should see all the pods respective to Falco, Falco Sidekick and Falco Sidekick-UI come up.

#### Next we check how services were created

```bash
>oc get svc -n falco
NAME                     TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)    AGE
falco-falcosidekick      ClusterIP   172.21.253.206   <none>        2801/TCP   70m
falco-falcosidekick-ui   ClusterIP   172.21.247.65    <none>        2802/TCP   35m  
```

Till this point, our setup is almost ready, except that we will need to expose the UI so that we can access publicly and also the sidekick svc so that we can test it (and later delete the sidekick route)

### Step 4: Create route for the services

First, we create a route for Sidekick to see if its able to pickup the events from Falco

```bash
>oc create route edge --service=falco-falcosidekick
route.route.openshift.io/falco-falcosidekick created

>oc get routes
NAME    HOST PORT      PATH      SERVICES                 PORT      TERMINATION   WILDCARD
falco-falcosidekick      falco-falcosidekick-falco.roks-cp4a-2face0433451d5f4f63e8f7ab10f8f12-0000.eu-de.containers.appdomain.cloud                falco-falcosidekick      http      edge          None
```
Next, we test the deployment of `Falcosidekick` with a simple browser test by pasting in the broswer URL:

```bash
https://falco-falcosidekick-falco.roks-cp4a-2face0433451d5f4f63e8f7ab10f8f12-0000.eu-de.containers.appdomain.cloud/ping

pong
```
We can safely delete this route now as we will not access Sidekick directly after this.

Next, we create a route for Sidekick-UI to see if its able to display the events from Falco & Sidekick

```bash
>oc create route edge --service=falco-falcosidekick-ui
route.route.openshift.io/falco-falcosidekick-ui created

>oc get routes
NAME    HOST PORT      PATH      SERVICES                 PORT      TERMINATION   WILDCARD
falco-falcosidekick      falco-falcosidekick-falco.roks-cp4a-2face0433451d5f4f63e8f7ab10f8f12-0000.eu-de.containers.appdomain.cloud                falco-falcosidekick      http      edge          None
falco-falcosidekick-ui   falco-falcosidekick-ui-falco.roks-cp4a-2face0433451d5f4f63e8f7ab10f8f12-0000.eu-de.containers.appdomain.cloud             falco-falcosidekick-ui   http      edge          None
```

Now if we open up this route URL in browser, we should be able to see the below web UI.

<p>
    <img src="diagrams/Faclo-ui.png" width="220" height="240" />
</p>


### Step 5: Real time test to see Falco at works

#### 1. Tail the logs in the first PS terminal

In one terminal, we tai the log in one pod of Falco

```bash
>oc logs -f falco-8lvvb
* Setting up /usr/src links from host
* Running falco-driver-loader with: driver=module, compile=yes, download=yes
* Unloading falco module, if present
* Trying to dkms install falco module

Kernel preparation unnecessary for this kernel.  Skipping...

Building module:
cleaning build area....
```

#### 2. Generate security event in the second PS terminal

In the second terminal, we do the following:

```bash
>oc exec -it falco-8lvvb /bin/bash
root@falco-8lvvb:/# cat /etc/shadow > /dev/null
```

#### 3. In the first terminal, we should see following events in the log

```bash
{"output":"17:18:29.082520347: Notice A shell was spawned in a container with an attached terminal (user=root user_loginuid=-1 k8s.ns=falco k8s.pod=falco-8lvvb container=6c9b72f1c563 shell=bash parent=runc cmdline=bash terminal=34816 container_id=6c9b72f1c563 image=<NA>) k8s.ns=falco k8s.pod=falco-8lvvb container=6c9b72f1c563","priority":"Notice","rule":"Terminal shell in container","time":"2021-05-29T17:18:29.082520347Z", "output_fields": {"container.id":"6c9b72f1c563","container.image.repository":null,"evt.time":1622308709082520347,"k8s.ns.name":"falco","k8s.pod.name":"falco-8lvvb","proc.cmdline":"bash","proc.name":"bash","proc.pname":"runc","proc.tty":34816,"user.loginuid":-1,"user.name":"root"}}

{"output":"17:19:14.363635208: Warning Sensitive file opened for reading by non-trusted program (user=root user_loginuid=-1 program=cat command=cat /etc/shadow file=/etc/shadow parent=bash gparent=runc ggparent=runc gggparent=runc container_id=6c9b72f1c563 image=<NA>) k8s.ns=falco k8s.pod=falco-8lvvb container=6c9b72f1c563 k8s.ns=falco k8s.pod=falco-8lvvb container=6c9b72f1c563","priority":"Warning","rule":"Read sensitive file untrusted","time":"2021-05-29T17:19:14.363635208Z", "output_fields": {"container.id":"6c9b72f1c563","container.image.repository":null,"evt.time":1622308754363635208,"fd.name":"/etc/shadow","k8s.ns.name":"falco","k8s.pod.name":"falco-8lvvb","proc.aname[2]":"runc","proc.aname[3]":"runc","proc.aname[4]":"runc","proc.cmdline":"cat /etc/shadow","proc.name":"cat","proc.pname":"bash","user.loginuid":-1,"user.name":"root"}}
```

#### 4. Verify in Falco Web UI these events

We can track down in the `Events` pane in the UI and search for `shell was spawned in` and then we will find the necessary event in the UI itself as below.

![Image](../blob/master/diagrams/Faclo-ui-security-alert.png?raw=true)

![Image](../blob/master/diagrams/Faclo-ui-security-alert2.png?raw=true)


## References

1. Falco blog: https://falco.org/blog/extend-falco-outputs-with-falcosidekick/
2. Falco github: 
    https://github.com/falcosecurity/falco
    https://github.com/falcosecurity/falcosidekick
    https://github.com/falcosecurity/falcosidekick-ui
