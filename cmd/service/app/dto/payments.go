package dto

type PaymentsDTO struct {
	Id       int `json:"id"`
	SenderId int `json:"sender_id"`
	Amount   int `json:"amount"`
}
