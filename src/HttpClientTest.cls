@isTest
public class HttpClientTest {
	@isTest static void testSend() {
		Test.setMock(HttpCalloutMock.class, new NTLMHttpCalloutMockImpl());
		HTTPRequest r = new HTTPRequest();
		string endpointurl = 'http://testNTLM.com';
		r.setEndpoint(endpointurl);
		r.setMethod('GET');

		HttpClient client = new HttpClient('domain\\username', 'password');

		HTTPResponse res = client.send(r);

		system.debug(res.getHeader('Content-Type'));
		System.assertEquals(200, res.getStatusCode());

		String contentType = res.getHeader('Content-Type');
		System.assert(contentType == 'application/json');
		
    String actualValue = res.getBody();
		system.debug(actualValue);
		String expectedValue = '{"foo":"bar"}';
		System.assertEquals(actualValue, expectedValue);
	}
}
