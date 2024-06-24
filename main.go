package main

import (
    "net/http"
    "errors"
    "github.com/gin-gonic/gin"
)

type vulnerability struct {
    ID           string  `json:"id"`
    Name         string  `json:"name"`
    URI          string  `json:"uri"`
    CWE          string  `json:"cwe"`
    Description  string  `json:"description"`
    CVSS         string  `json:"cvss"`
    Score        string  `json:"score"`
    Mitre        string  `json:"mitre"`
    Remediation  string  `json:"remediation"`
}

var vulnerabilities = []vulnerability{
    {ID: "1", Name: "XSS", URI: "/profile", CWE: "CWE-79", Description: "Stored Cross-site Scripting", CVSS: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", Score: "8.8", Mitre: "Web Shell", Remediation: "Sanitize  user-supplied parameters and encode all output that comes from untrusted sources before displaying it to users"},
    {ID: "2", Name: "CSRF", URI: "/profile", CWE: "CWE-352", Description: "The applications configuration allows an attacker to trick authenticated users into executing actions without their consent.", CVSS: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", Score: "4.3", Mitre: "Trusted Relationship", Remediation: "Use CSRF token, validate the referer, use SameSite cookies"},
    {ID: "3", Name: "Injection", URI: "/login", CWE: "CWE-89", Description: "Admin login by using SQLi", CVSS: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L", Score: "6.3", Mitre: "Exploitation for Client Execution", Remediation: "Sanitize special characters or use prepared statements"},
    {ID: "4", Name: "Asymmetric DoS", URI: "/register", CWE: "CWE-405", Description: "A single malicious request that breaks the application or consumes an enormous amount of resources.", CVSS: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", Score: "7.5", Mitre: "Endpoint Denial of Service: Application Exhaustion Flood", Remediation: "Implement rate limit, use timouts to limit the amount of time a request can consume resources, try using separate worker pool for expensive operations, monitor server performance and resource usage to detect and mitigate potential DoS attack"},
    {ID: "5", Name: "Symetric DoS", URI: "/login", CWE: "CWE-400", Description: "The server crash is generated with multiple requests", CVSS: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", Score: "6.5", Mitre: "Network Denial of Service: Direct Network Flood", Remediation: "Set a rate limit and a maximum response time"},
    {ID: "6", Name: "DDoS", URI: "*.png", CWE: "CWE-400", Description: "Distributed Denial-of-service", CVSS: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", Score: "6.5", Mitre: "Network Denial of Service: Reflection Amplification", Remediation: "Reduce possible surface of attack (implement a load balancer), block communication from outdated or unused ports, use cache to serve fewer requests by origin servers (Using a CDN) and rate limit"},
}

func getVulns(context *gin.Context){
    context.IndentedJSON(http.StatusOK, vulnerabilities)
}

func getVulnById(id string) (*vulnerability, error) {
    for i, v := range vulnerabilities {
        if v.ID == id {
            return &vulnerabilities[i], nil
        }
    }

    return nil, errors.New("Vulnerability not found")
}

func getVuln(context *gin.Context){
    id := context.Param("id")
    vulnerability, err := getVulnById(id)

    if err != nil {
        context.IndentedJSON(http.StatusNotFound, gin.H{"message": "Vulnerability not found"})
        return
    }

    context.IndentedJSON(http.StatusOK, vulnerability)
}

func main() {
    router := gin.Default()
    router.GET("/vulnerabilities", getVulns)
    router.GET("/vulnerabilities/:id", getVuln)
    router.Run()
}
