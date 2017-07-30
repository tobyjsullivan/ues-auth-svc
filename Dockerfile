FROM golang
ADD . /go/src/github.com/tobyjsullivan/ues-auth-svc
RUN  go install github.com/tobyjsullivan/ues-auth-svc
CMD /go/bin/ues-auth-svc

