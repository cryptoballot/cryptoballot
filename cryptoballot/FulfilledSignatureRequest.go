package cryptoballot

type FulfilledSignatureRequest struct {
	SignatureRequest
	BallotSignature Signature // BallotClerk signature signing off on the validity of the ballot
}

func NewFulfilledSignatureRequest(sigReq SignatureRequest, sig Signature) *FulfilledSignatureRequest {
	return &FulfilledSignatureRequest{
		sigReq,
		sig,
	}
}

func (fulfilled *FulfilledSignatureRequest) String() string {
	return fulfilled.SignatureRequest.String() + "\n\n" + fulfilled.BallotSignature.String()
}
