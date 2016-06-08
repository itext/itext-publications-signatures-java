/*

    This file is part of the iText (R) project.
    Copyright (c) 1998-2016 iText Group NV

*/

package com.itextpdf.samples;

import com.itextpdf.kernel.geom.Rectangle;

import java.util.Date;
import java.util.List;

public class SignatureInfo {
    private int revisionNumber;
    private boolean signatureCoversWholeDocument;
    private Rectangle signaturePosition;
    private String digestAlgorithm;
    private String encryptionAlgorithm;
    private String filterSubtype;
    private String signerName;
    private String alternativeSignerName;
    private Date signDate;
    private Date timeStamp;
    private String timeStampService;
    private String location;
    private String reason;
    private String contactInfo;
    private boolean isCertifiaction;
    private boolean isFieldsFillAllowed;
    private boolean isAddingAnnotationsAllowed;
    private List<String> fieldsLocks;
    private List<CertificateInfo> certificateInfos;
    private String signatureName;

    public void setRevisionNumber(int revisionNumber) {
        this.revisionNumber = revisionNumber;
    }

    public int getRevisionNumber() {
        return revisionNumber;
    }

    public void setSignatureCoversWholeDocument(boolean signatureCoversWholeDocument) {
        this.signatureCoversWholeDocument = signatureCoversWholeDocument;
    }

    public boolean isSignatureCoversWholeDocument() {
        return signatureCoversWholeDocument;
    }

    public void setSignaturePosition(Rectangle signaturePosition) {
        this.signaturePosition = signaturePosition;
    }

    public Rectangle getSignaturePosition() {
        return signaturePosition;
    }

    public void setDigestAlgorithm(String digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }

    public String getDigestAlgorithm() {
        return digestAlgorithm;
    }

    public void setEncryptionAlgorithm(String encryptionAlgorithm) {
        this.encryptionAlgorithm = encryptionAlgorithm;
    }

    public String getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    public void setFilterSubtype(String filterSubtype) {
        this.filterSubtype = filterSubtype;
    }

    public String getFilterSubtype() {
        return filterSubtype;
    }

    public void setSignerName(String signerName) {
        this.signerName = signerName;
    }

    public String getSignerName() {
        return signerName;
    }

    public void setAlternativeSignerName(String alternativeSignerName) {
        this.alternativeSignerName = alternativeSignerName;
    }

    public String getAlternativeSignerName() {
        return alternativeSignerName;
    }

    public void setSignDate(Date signDate) {
        this.signDate = signDate;
    }

    public Date getSignDate() {
        return signDate;
    }

    public void setTimeStamp(Date timeStamp) {
        this.timeStamp = timeStamp;
    }

    public Date getTimeStamp() {
        return timeStamp;
    }

    public void setTimeStampService(String timeStampService) {
        this.timeStampService = timeStampService;
    }

    public String getTimeStampService() {
        return timeStampService;
    }

    public void setLocation(String location) {
        this.location = location;
    }

    public String getLocation() {
        return location;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public String getReason() {
        return reason;
    }

    public void setContactInfo(String contactInfo) {
        this.contactInfo = contactInfo;
    }

    public String getContactInfo() {
        return contactInfo;
    }

    public void setIsCertifiaction(boolean isCertifiaction) {
        this.isCertifiaction = isCertifiaction;
    }

    public boolean isCertifiaction() {
        return isCertifiaction;
    }

    public void setIsFieldsFillAllowed(boolean isFieldsFillAllowed) {
        this.isFieldsFillAllowed = isFieldsFillAllowed;
    }

    public boolean isFieldsFillAllowed() {
        return isFieldsFillAllowed;
    }

    public void setIsAddingAnnotationsAllowed(boolean isAddingAnnotationsAllowed) {
        this.isAddingAnnotationsAllowed = isAddingAnnotationsAllowed;
    }

    public boolean isAddingAnnotationsAllowed() {
        return isAddingAnnotationsAllowed;
    }

    public void setFieldsLocks(List<String> fieldsLocks) {
        this.fieldsLocks = fieldsLocks;
    }

    public List<String> getFieldsLocks() {
        return fieldsLocks;
    }

    public void setCertificateInfos(List<CertificateInfo> certificateInfos) {
        this.certificateInfos = certificateInfos;
    }

    public List<CertificateInfo> getCertificateInfos() {
        return certificateInfos;
    }

    public void setSignatureName(String signatureName) {
        this.signatureName = signatureName;
    }

    public String getSignatureName() {
        return signatureName;
    }
}
