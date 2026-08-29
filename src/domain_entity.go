package domain

type QuantumAuditEntity struct {
	ID        string `json:"id"` 
	Status    string `json:"status"` 
	RiskLevel string `json:"risk_level"` 
}

func NewQuantumAuditEntity(id string) *QuantumAuditEntity {
	return &QuantumAuditEntity{
		ID:        id,
		Status:    "AUDITED",
		RiskLevel: "LOW",
	}
}
