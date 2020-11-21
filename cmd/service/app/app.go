package app

import (
	"context"
	"encoding/json"
	"github.com/go-chi/chi"
	"log"
	"net/http"
	"service/cmd/service/app/dto"
	"service/cmd/service/app/middleware/authenticator"
	"service/cmd/service/app/middleware/authorizator"
	"service/cmd/service/app/middleware/identificator"
	"service/pkg/business"
	"service/pkg/security"
)

type Server struct {
	securitySvc *security.Service
	businessSvc *business.Service
	router      chi.Router
}

func NewServer(securitySvc *security.Service, businessSvc *business.Service, router chi.Router) *Server {
	return &Server{securitySvc: securitySvc, businessSvc: businessSvc, router: router}
}

func (s *Server) Init() error {
	s.router.Post("/users", s.handleRegister)
	s.router.Put("/users", s.handleLogin)

	identificatorMd := identificator.Identificator
	authenticatorMd := authenticator.Authenticator(
		identificator.Identifier, s.securitySvc.UserDetails,
	)

	// функция-связка между middleware и security service
	// (для чистоты security service ничего не знает об http)
	roleChecker := func(ctx context.Context, roles ...string) bool {
		userDetails, err := authenticator.Authentication(ctx)
		if err != nil {
			return false
		}
		return s.securitySvc.HasAnyRole(ctx, userDetails, roles...)
	}
	adminRoleMd := authorizator.Authorizator(roleChecker, security.RoleAdmin)
	userRoleMd := authorizator.Authorizator(roleChecker, security.RoleUser)

	s.router.Get("/public", s.handlePublic)
	s.router.With(identificatorMd, authenticatorMd, adminRoleMd).Get("/admin", s.handleAdmin)
	s.router.With(identificatorMd, authenticatorMd, userRoleMd).Get("/user", s.handleUser)

	s.router.With(identificatorMd, authenticatorMd, userRoleMd).Post("/user/payments", s.createPayments)
	s.router.With(identificatorMd, authenticatorMd, userRoleMd).Get("/user/payments", s.getPayments)
	s.router.With(identificatorMd, authenticatorMd, adminRoleMd).Get("/admin/payments", s.getPaymentsAdmin)

	return nil
}

func (s *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	s.router.ServeHTTP(writer, request)
}

func (s *Server) handleRegister(writer http.ResponseWriter, request *http.Request) {
	login := request.PostFormValue("login")
	if login == "" {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	password := request.PostFormValue("password")
	if password == "" {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	token, err := s.securitySvc.Register(request.Context(), login, password)
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	data := &dto.TokenDTO{Token: token}
	respBody, err := json.Marshal(data)
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	writer.Header().Set("Content-Type", "application/json")
	_, err = writer.Write(respBody)
	if err != nil {
		log.Print(err)
	}
}

func (s *Server) handleLogin(writer http.ResponseWriter, request *http.Request) {
	login := request.PostFormValue("login")
	if login == "" {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	password := request.PostFormValue("password")
	if password == "" {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	token, err := s.securitySvc.Login(request.Context(), login, password)
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	data := &dto.TokenDTO{Token: token}
	respBody, err := json.Marshal(data)
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	writer.Header().Set("Content-Type", "application/json")
	_, err = writer.Write(respBody)
	if err != nil {
		log.Print(err)
	}
}

// Доступно всем
func (s *Server) handlePublic(writer http.ResponseWriter, request *http.Request) {
	_, err := writer.Write([]byte("public"))
	if err != nil {
		log.Print(err)
	}
}

// Только пользователям с ролью ADMIN
func (s *Server) handleAdmin(writer http.ResponseWriter, request *http.Request) {
	_, err := writer.Write([]byte("admin"))
	if err != nil {
		log.Print(err)
	}
}

// Только пользователям с ролью USER
func (s *Server) handleUser(writer http.ResponseWriter, request *http.Request) {
	_, err := writer.Write([]byte("user"))
	if err != nil {
		log.Print(err)
	}
}

func (s *Server) getPayments(w http.ResponseWriter, r *http.Request) {
	userDetails, err := authenticator.Authentication(r.Context())
	if err != nil {
		prepareResponseErr(w, err, http.StatusBadRequest)
		return
	}

	details, ok := userDetails.(*security.UserDetails)
	if !ok {
		return
	}

	payments := []*dto.PaymentsDTO{}
	payments, err = s.securitySvc.GetPayments(r.Context(), details.ID)

	if err != nil {
		prepareResponseErr(w, err, http.StatusBadRequest)
		return
	}

	prepareResponse(w, payments, http.StatusOK)
	return
}

func (s *Server) getPaymentsAdmin(w http.ResponseWriter, r *http.Request) {

	payments := []*dto.PaymentsDTO{}
	payments, err := s.securitySvc.GetPaymentsAdmin(r.Context())

	if err != nil {
		prepareResponseErr(w, err, http.StatusBadRequest)
		return
	}

	prepareResponse(w, payments, http.StatusOK)
	return
}

func (s *Server) createPayments(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	payment := &dto.PaymentsDTO{}
	err := decoder.Decode(payment)
	if err != nil {
		prepareResponseErr(w, err, http.StatusBadRequest)
		return
	}


	userDetails, err := authenticator.Authentication(r.Context())
	if err != nil {
		prepareResponseErr(w, err, http.StatusBadRequest)
		return
	}

	details, ok := userDetails.(*security.UserDetails)
	if !ok {
		return
	}

	data := dto.PaymentsDTO{}
	data, err = s.securitySvc.CreatePayments(r.Context(), details.ID, payment.Amount)

	if err != nil {
		prepareResponseErr(w, err, http.StatusBadRequest)
		return
	}

	prepareResponse(w, data, http.StatusOK)
	return

}

func prepareResponseErr(w http.ResponseWriter, err error, wHeader int) {
	log.Println(err)
	data := &dto.ErrDTO{Err: err.Error()}
	prepareResponse(w, data, wHeader)
}

func prepareResponse(w http.ResponseWriter, dto interface{}, wHeader int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(wHeader)

	respBody, err := json.Marshal(dto)
	if err != nil {
		log.Println(err)
		return
	}

	_, err = w.Write(respBody)
	if err != nil {
		log.Println(err)
	}
}
