/*
 * This class wraps calls to the Http.send method defined by the system and
 * adds support for NTLM authentication.
 *
 * @author Nate Wallace
 */
public class HttpClient {

    /*
     * Supports the getUser/setUser methods.
     */
    private string mUser;
    
    /*
     * Supports the getPassword/setPassword methods.
     */
    private string mPassword;
    
    /*
     * Supports the setIsPreAuthenticate/getIsPreAuthenticate methods.
     */
    private boolean mIsPreAuthenticate;
    
    /*
     * Used to send http messages.
     */
    private Http mHttp;
    
    /*
     * Used for NTLM authentication.
     */
    private NTLMAuth mNtlm;
    
    /*
     * Constructor.
     */
    public HttpClient() {
        this(null, null, false);
    }
    
    /*
     * Constructor.
     *
     * @param user User.
     * @param password Password.
     */
    public HttpClient(string user, string password) {
        this(user, password, false);
    }
    
    /*
     * Constructor.
     *
     * @param user User.
     * @param password Password.
     * @param isPreAuthenticate IsPreAuthenticate.
     */
    public HttpClient(string user, string password, boolean isPreAuthenticate) {
        setUser(user);
        setPassword(password);
        setIsPreAuthenticate(isPreAuthenticate);
        mHttp = new Http();
        mNtlm = new NTLMAuth();
    }
    
    /*
     * Set the User part of authentication credentials.  This should be the full domain and user name for NTLM authentication.  i.e. UP\DUX07.
     *
     * @param value The User part of authentication credentials.
     */
    public void setUser(string value) {
        mUser = value;
    }
    
    /*
     * Get the User part of authentication credentials.  If not set this defaults to null.
     *
     * @return The User part of authentication credentials.
     */
    public string getUser() {
        return mUser;
    }
    
    /*
     * Set the Password part of authentication credentials.
     *
     * @param value The Password part of authentication credentials.
     */
    public void setPassword(string value) {
        mPassword = value;
    }
    
    /*
     * Get the Password part of authentication credentials.
     *
     * @return The Password part of authentication credentials.  If not set this defaults to null.
     */ 
    public string getPassword() {
        return mPassword;
    }
    
    /*
     * When set to true this object will send authentication information with the first message instead of waiting for a challenge from the server.
     * When set to false this object will not send authentication information until the server challenges us.
     *
     * @param value The IsPreAuthenticate value to set.
     */
    public void setIsPreAuthenticate(boolean value) {
        mIsPreAuthenticate = value;
    }
    
    /*
     * When this returns true this object will send authentication information with the first message instead of waiting for a challenge from the server.
     * When this returns false this object will not send authentication information until the server challenges us.
     * If not set this defaults to false.
     *
     * @returns value The IsPreAuthenticate value that is set.
     */
    public boolean getIsPreAuthenticate() {
        return mIsPreAuthenticate;
    }
    
    /*
     * Sends an HttpRequest and returns the response.
     * 
     * @param request The request to send.  Note that only the Endpoint, Method, Compressed, and Body values are used.
     * @param headers The headers to include in the request.
     * @return The response from the server.
     */
    public HttpResponse send(HttpRequest request, Map<string, string> headers) {
    	
    	integer authStep = 0;
        
        HttpRequest req = Clone(request, headers);
        
        if (getIsPreAuthenticate()) {
            req.setHeader('Authorization', 'NTLM ' + mNtlm.getType1Message());
            req.setBody('');
            authStep = 1;
        }
            
        HttpResponse resp = mHttp.send(req);
        
        // process a 401 response
        while (resp.getStatusCode() == 401) {
            if (authStep > 1)
                return resp;
            resp = handle401Response(resp, request, headers, authStep);
            authStep++;
        }                   
        
        return resp; 
    }
    
    /*
     * Sends an HttpRequest and returns the response.
     *
     * @param request The request to send.  Note that only the Endpoint, Method, Compressed, and Body values are used.
     * @return The response from the server.
     */
    public HttpResponse send(HttpRequest request) {
        
        return send(request, null);        
    }
    
    /*
     * Handle the 401 response and perform NTLM authentication.
     *
     * @param response The response that came back from the server with a 401.
     * @param request The original request.
     * @param headers The headers for the original request.
     * @param authStep The current step we are on in the authorization sequence.
     * @return A new response from the server after sending out an appropriate NTLM message in response to the 401.
     */
    private HttpResponse handle401Response(HttpResponse response, HttpRequest request, Map<string, string> headers, integer authStep) {  

        if (authStep == 0) {    // send initial NTLM type 1 message         
            HttpRequest req = Clone(request, headers);       
            req.setHeader('Authorization', 'NTLM ' + mNtlm.getType1Message());
            req.setBody('');    
            return mHttp.send(req);
        }
        else if (authStep == 1) { // send NTLM type 3 message in response to a type 2 message received from the server.
            string ntlmMessage = ParseHttpNtlmHeader(response);
            if (ntlmMessage == null || ntlmMessage == '')
                return response; // Server didn't send message after we sent it our type 1 message so we give up.
                
            HttpRequest req = Clone(request, headers);
            req.setHeader('Authorization', 'NTLM ' + mNtlm.getType3Message(ntlmMessage, getUser(), getPassword()));
            return mHttp.send(req);
        }
        else { // we have given up after the second step
            return response;
        }
    }
    
    /*
     * Clones the given request.
     *
     * @param request The request to clone.
     * @param headers The headers to include in the request.
     * @return The new object that is a clone of the request parameter.
     */
    private HttpRequest Clone(HttpRequest request, Map<string, string> headers) {
        HttpRequest req = new HttpRequest();
        req.setEndpoint(request.getEndpoint());
        req.setMethod(request.getMethod());
        req.setCompressed(request.getCompressed());              
        
        req.setBodyAsBlob(request.getBodyAsBlob());
        
        if (headers != null)
        	for (string key : headers.keySet())
        		req.setHeader(key, headers.get(key));
        
        return req;
    }
    
    /*
     * Parses the given response headers for the NTLM message.
     *
     * @param response The response whose headers will be parsed.
     * @return An empty string if the header found indicates NTLM authentication should be initiated. i.e. When the header WWW-Authenticate: Negotiate,NTLM is found.
     *        An NTLM message when the header found includes an NTLM message.  i.e. WWW-Authenticate: NTLM TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA= will return TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA=.
     *        A null value will be returned if there is no NTLM header or the authentication specified in the header doesn't support NTLM authentication.
     */
    public string ParseHttpNtlmHeader(HttpResponse response) {
        if (response == null)
            throw new RuntimeException('response is null.');
            
        string header = response.getHeader('WWW-Authenticate');
        if (header == null)
            return null;
            
        if (header.startsWith('NTLM '))
            return header.subString(5, header.length());
            
        string[] headerValues = header.split(',', -1);
        for (string headerValue : headerValues) {
            if (headerValue == 'NTLM')
                return '';
        }
        
        return null;
    }   
}
