package com.itextpdf.samples;

import java.util.ArrayList;
import java.util.List;

class SignedDocumentInfo {

    private ArrayList<String> signatureNames;
    private int numberOfTotalRevisions;
    private List<SignatureInfo> signatureInfos;

    public void setNumberOfTotalRevisions(int numberOfTotalRevisions) {
        this.numberOfTotalRevisions = numberOfTotalRevisions;
    }

    public int getNumberOfTotalRevisions() {
        return numberOfTotalRevisions;
    }

    public void setSignatureInfos(List<SignatureInfo> signatureInfos) {
        this.signatureInfos = signatureInfos;
    }

    public List<SignatureInfo> getSignatureInfos() {
        return signatureInfos;
    }
}
