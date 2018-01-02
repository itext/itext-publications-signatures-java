/*
    This file is part of the iText (R) project.
    Copyright (c) 1998-2018 iText Group NV
    Authors: iText Software.

    For more information, please contact iText Software at this address:
    sales@itextpdf.com
 */
package com.itextpdf.samples;

import java.security.Principal;
import java.util.Date;

public class CertificateInfo {
    private Principal issuer;
    private Principal subject;
    private Date validFrom;
    private Date validTo;

    public void setIssuer(Principal issuer) {
        this.issuer = issuer;
    }

    public Principal getIssuer() {
        return issuer;
    }

    public void setSubject(Principal subject) {
        this.subject = subject;
    }

    public Principal getSubject() {
        return subject;
    }

    public void setValidFrom(Date validFrom) {
        this.validFrom = validFrom;
    }

    public Date getValidFrom() {
        return validFrom;
    }

    public void setValidTo(Date validTo) {
        this.validTo = validTo;
    }

    public Date getValidTo() {
        return validTo;
    }
}
