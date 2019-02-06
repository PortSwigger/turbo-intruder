package burp;

import java.net.URL;

class TurboScanIssue implements IScanIssue {
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;
    private String confidence;
    private String remediation;

    TurboScanIssue(
            IHttpService httpService,
            URL url,
            IHttpRequestResponse[] httpMessages,
            String name,
            String detail,
            String severity,
            String confidence,
            String remediation) {
        this.name = name;
        this.detail = detail;
        this.severity = severity;
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.confidence = confidence;
        this.remediation = remediation;
    }

    @Override
    public URL getUrl() {
        return url;
    }

    @Override
    public String getIssueName() {
        return name;
    }

    @Override
    public int getIssueType() {
        return 0;
    }

    @Override
    public String getSeverity() {
        return severity;
    }

    @Override
    public String getConfidence() {
        return confidence;
    }

    @Override
    public String getIssueBackground() {
        return null;
    }

    @Override
    public String getRemediationBackground() {
        return null;
    }

    @Override
    public String getIssueDetail() {
        return detail;
    }

    @Override
    public String getRemediationDetail() {
        return remediation;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }

    public String getHost() {
        return null;
    }

    public int getPort() {
        return 0;
    }

    public String getProtocol() {
        return null;
    }
}