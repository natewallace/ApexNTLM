@isTest
global class NTLMHttpCalloutMockImpl implements HttpCalloutMock {
	global HttpResponse respond(HTTPRequest req) {
		// Create a fake response
		HttpResponse res = new HttpResponse();
		string endPoint = req.getEndpoint();

		System.assertEquals('GET', req.getMethod());
		string Authorization = req.getHeader('Authorization');

		if (String.isBlank(Authorization) || String.isEmpty(Authorization))
		{
			System.debug('Step 0');
			res.setHeader('WWW-Authenticate', 'NTLM');
			res.setStatusCode(401);

		} else {

			NTLMAuth mNtlm = new NTLMAuth();
			if (Authorization.contains('NTLM'))
			{
				if (Authorization == 'NTLM ' + mNtlm.getType1Message()) {
					System.debug('Step 1');
					
					Integer[] message2 = new Integer[] { 78, 84, 76, 77, 83, 83, 80, 0, 2, //header of type 2 (9 in total)
						4, 5, 6, 8, 10, 11, 15, 16, 20, 22, 26, 29, 31, 45, 46, 49, 58, 66, 74, 85, 86, 97, 100 }; //numbers from random org
					string message2String = BitConverter.encodeBase64String(message2);

					res.setHeader('WWW-Authenticate', 'NTLM ' + message2String);
					res.setStatusCode(401);

				}
				else
				{
					System.debug('Step 2');
					req.setHeader('Authorization', 'NTLM ');

					res.setHeader('Content-Type', 'application/json');
					res.setStatusCode(200);

					if (endPoint == 'http://testNTLM.com')
					{
						res.setBody('{"foo":"bar"}');
					}
				}
			}
			
			return res;
		}
	}
