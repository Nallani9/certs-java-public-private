package com.hobbyproject.service;

import com.nimbusds.jose.JOSEException;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.text.ParseException;

public class Main {

	public static void main(String[] args) throws GeneralSecurityException, JOSEException, ParseException, IOException, URISyntaxException {

		//FileUtils.readFileToString(new File(""),"UTF-8");

		//MyPublicKeyTest.publicKeyFromFile();
		//MyPublicKeyTest.publicKeyFromString("MIIC1jCCAb4CAQAwgZAxCzAJBgNVBAYTAlVTMREwDwYDVQQIDAhWaXJnaW5pYTERMA8GA1UEBwwIUmljaG1vbmQxEDAOBgNVBAoMB25hbGxhbmkxDDAKBgNVBAsMA3NyaTETMBEGA1UEAwwKbmFsbGFuaXNyaTEmMCQGCSqGSIb3DQEJARYXc3Jpa2FudGhqYXdzOEBnbWFpbC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7yxNhrHgComuqqG1SB/pwxXVfaAVpRIXBZQOg1xyUW+24AEUC18e+M8z4213/iJH9Oba91qOGvncsOhmrLKPU9AD2Hxr38bWeZIvc/idKdrAn/GcV2ZlsPNJKw7JrS1grgo1g2cMUe+yjqetCgOchACSqivZhfd1CMco93oGi+NT1K6QfvuYw55FT6jrSC1rSxH+hKhOTfIw/PRZNe9In1UhcH3zJ1DTMe6tf1MVT/IJttfvSlN2DHCdtP27mqwMlsJXImrwQj4aQGmpajMCrDgumMVZcNue0QLdR1koOGYRZp4Xuqc+On5JLXNgUGqiMImXNc+fWHQPoiLHapB3HAgMBAAGgADANBgkqhkiG9w0BAQsFAAOCAQEAckMDVgan5Rb/wabKDdOaoEhxXi4bLmPBQTfRQ1oukDmaLqN5HiVuIa8x6F5scPav+2ZnLjfDcj2hiVaU7kza17iU7G+AfdEyzBYOODSD7g4oR1ix2hkmY4+3S6l5mXebubvgQung5ysd0XfUcHqxRqEou0NjWotQ/M0q46Y5nNemi1uScBv6GiLK5Wr7Hm6eo927wT+RZfP/tFgiETBQR4nNtfpU3mCgJuFrmOz/sFKNr301nUXkLv1XN0/j2l9G/CRzxrUzDBIWN+2ppB+ex6Qq4p6ATwewWPZnynK7ujCCczsaoHNx7MSQTSSSnlF/9N+fkocF5YCoYIh8bSv8/w==");

		//MyPrivateKeyTest.getPrivateKeyFromString("MIIEpAIBAAKCAQEAu8sTYax4AqJrqqhtUgf6cMV1X2gFaUSFwWUDoNcclFvtuABFAtfHvjPM+Ntd/4iR/Tm2vdajhr53LDoZqyyj1PQA9h8a9/G1nmSL3P4nSnawJ/xnFdmZbDzSSsOya0tYK4KNYNnDFHvso6nrQoDnIQAkqor2YX3dQjHKPd6BovjU9SukH77mMOeRU+o60gta0sR/oSoTk3yMPz0WTXvSJ9VIXB98ydQ0zHurX9TFU/yCbbX70pTdgxwnbT9u5qsDJbCVyJq8EI+GkBpqWozAqw4LpjFWXDbntEC3UdZKDhmEWaeF7qnPjp+SS1zYFBqojCJlzXPn1h0D6Iix2qQdxwIDAQABAoIBAFuWqIY7knBefLpH2MFoSLmVZDA60GDN3Zo7xPA92Z910lOqNf4z9SQLqY05l/eXyPPCoSCnPSvrWr4EPB6i7+hddNaUxxdkGFr+2MPYZJtJlZJ65F/gt5X1d+6k0TDJF2BpFMDGlAE6i2gq6CWQLqmGo1tV2OIle7LcC7HvAjTT50yZSF19XRbDuwO/Ar5GTZfmK9A03f8sV0Vxcd0BIDAp4BI+z/lSjozRUH/cU/AEYufGZqWNPJVNR1cTOgWnQZ6n8N4jgEmf4izLOGdvNiOUcXy/PNiXk3yhB8Hc+ZZiV9Lpq0G4p1lDz+DMLLRcN67GRHKYqMGNaiy5B0IY5AkCgYEA3insdVxMwGs5tZynyUg+LHP0d7qCUmmSneLG8ys3JOg5KOPr7YtXZB7unG0ORuCKL1shqLR8/2J6Ia7hXZ+dUtRD2IwmKT9nTUMuHEWjh8C2d1MAsz1/GN98Tl3V6lrrOVcaL6q02uSgSnr6nfoYaQGKFK2MHQ0pU2Yz6zqtaY0CgYEA2GUPXBLcISRNTvMENSd4rzrQGOTEha26PYrekUolfsKqNZcT+i7C2WGJRHkLQ1kNsFK3EMLeYlcMhkHkF/t1uAYPpsDmzFScm6YWRZ5ghg/w4EiEDpDKX229bknESvHvFxugCYia3fNQC3WXHbhy15CyzT7HwJRYgRXN1gSEzaMCgYEAmpKUwLstc5unFWMfon4vNAKhj0QnNGvb5RpJzhq9TWJ9kqOyHR6b+T9ESXXfPxUvT++aJaUeaxn7W8AvcVKCxYSGh/5K9tv0Zd9eD7GsK+G7kp4fmJYq/gVQmb3T/jCwBL9DqvKczsfPdsLF6HB/11+I0QZGvFfR7wLnEL1MtmkCgYEAurew4iyv3rT5NAdC+S5+1wxzZRd4bzRxQAskcs88vTzxK16Z8UUKAhJEJF4hltIvmpY0ufS7eLVN7EbMrtjeQZSRSrymKWdU3oUYMKgw91yn5o8Ly5mp1V/WlWR3SIerWxAOLku9/Yel6M1lQFLYXSLQ9YKXT5dxKqkKvAGYKesCgYB7spLhkfsyTOXVadU7/yGlN6MbGbXI0MF5HjFWNY+PB5xQqxwQxued1WEwcgi7EQ7u4raS+hPN0KWH8mJFCol2KCXzdvVdd2h5xbNb7b42/xN2ZCEAYA8n0ZT0wOa2RPTnR95jld1jZ/OMMHV7au5QlXGyKlAGO9ZuUns6aNDhvQ==");
		//MyPrivateKeyTest.getPrivateKey();
		//MyPrivateKeyTest.createPrivateKeyFromFileWithBouncy();  //WORKING
		//MyPrivateKeyTest.getPrivateKeyFromBouncy2(); //Working
		//Util.getPrivateKey();
		MyPublicKeyTest.publicKeyFromString("MIIEAzCCAuugAwIBAgIURMswEo/kbjL1xNfOARx2j5DSj1IwDQYJKoZIhvcNAQELBQAwgZAxCzAJBgNVBAYTAlVTMREwDwYDVQQIDAhWaXJnaW5pYTERMA8GA1UEBwwIUmljaG1vbmQxEDAOBgNVBAoMB25hbGxhbmkxDDAKBgNVBAsMA3NyaTETMBEGA1UEAwwKbmFsbGFuaXNyaTEmMCQGCSqGSIb3DQEJARYXc3Jpa2FudGhqYXdzOEBnbWFpbC5jb20wHhcNMjEwMzMxMDQwMTIzWhcNMzEwMzI5MDQwMTIzWjCBkDELMAkGA1UEBhMCVVMxETAPBgNVBAgMCFZpcmdpbmlhMREwDwYDVQQHDAhSaWNobW9uZDEQMA4GA1UECgwHbmFsbGFuaTEMMAoGA1UECwwDc3JpMRMwEQYDVQQDDApuYWxsYW5pc3JpMSYwJAYJKoZIhvcNAQkBFhdzcmlrYW50aGphd3M4QGdtYWlsLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALvLE2GseAKia6qobVIH+nDFdV9oBWlEhcFlA6DXHJRb7bgARQLXx74zzPjbXf+Ikf05tr3Wo4a+dyw6Gasso9T0APYfGvfxtZ5ki9z+J0p2sCf8ZxXZmWw80krDsmtLWCuCjWDZwxR77KOp60KA5yEAJKqK9mF93UIxyj3egaL41PUrpB++5jDnkVPqOtILWtLEf6EqE5N8jD89Fk170ifVSFwffMnUNMx7q1/UxVP8gm21+9KU3YMcJ20/buarAyWwlciavBCPhpAaalqMwKsOC6YxVlw257RAt1HWSg4ZhFmnhe6pz46fkktc2BQaqIwiZc1z59YdA+iIsdqkHccCAwEAAaNTMFEwHQYDVR0OBBYEFI1FlL+6230r2vU2JY52ZSYJ0RHCMB8GA1UdIwQYMBaAFI1FlL+6230r2vU2JY52ZSYJ0RHCMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAKr85kfYDrpWmq9ugB6PBq6K3dhw4THEuKOAhvefra1yWi+aD4ooQjr29JzHbOmqYgmGF6DpYBVjS7NAbfFLXf6mPfOZWft295rX9Ju51hz1WoCKqvRc+xoFngEgd7q6Q75zqcO+Yd64hSfKey2H35UQ+IQnEBRGDbs3BIixzB60871wosYRDHsOaNiSnltu448dgcQJD0xGvB+L/KnhGT4AZ42xKgktea5slIyp2IqoDaPgvZKxAPjccPlRIlEiQLBnDkoYTM4p/VA/1URdJiYnZgkTZs+SN0YgS2IuNwaawdc9ZvwgdFsNZZGd/oChYvt4Zrk6T09AIYcz0kzH1Uw=");
	}
}