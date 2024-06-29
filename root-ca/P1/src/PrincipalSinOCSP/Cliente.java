package PrincipalSinOCSP;

import Mensajes.*;
import Cifrar_Descifrar.*;

import java.util.*;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import Cifrar_Descifrar.Crypto;

import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.Principal;
import java.security.cert.CertPathBuilder;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;


public class Cliente {
	
	public static KeyStore ks;
	public static KeyStore ts;
	public static Scanner keyboard = new Scanner(System.in);
	public static String path = "./documentos/";
	public static String pathCifrado = "./textoCifrado/";
	public static String algoritmo = "AES";
	public static int longclave = 128;
	public static TreeMap<String,byte[]> archivosCliente =new TreeMap <String,byte[]>();
	public static TreeMap<byte[],byte[]> hashRespuestaServidor =new TreeMap <byte[],byte[]>();
	public static String 	raizMios     = "/home/miguel/SEG/";

	public static void main (String[] args) {
		String[]   cipherSuitesDisponibles = null;
		
		if (args.length != 4) {
			System.out.println("Los argumentos son : keyStoreFile truststoreFile contraseñaKeystore IpOCSPResponder");
			System.exit(-1);
		}
		
		String keyStoreFile = args[0];
		String truststoreFile = args[1];
		String contraseñaKeystore = args[2];
		String IpOCSPResponder = args[3];

		try {
			definirAlmacenesCliente();
			definirRevocacionOCSPStapling();
			//definirRevocacionOCSP();
		
			/*
		     * Set up a key manager for client authentication
		     * if asked by the server.  Use the implementation's
		     * default TrustStore and secureRandom routines.
		     */
		    SSLSocketFactory factory = null;
		    
			try {
				SSLContext ctx;
				KeyManagerFactory kmf;
				KeyStore ks;
				char[] passphrase = "1234".toCharArray();

				/********************************************************************************
				* Construir un contexto, pasandole el KeyManager y y TrustManager 
				* Al TrustManager se le incorpora el chequeo de certificados revocados por Ocsp. 
				*   
				********************************************************************************/
				// --- Trust manager.
				
				//  1. Crear PKIXRevocationChecker

				CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX");
				PKIXRevocationChecker rc = (PKIXRevocationChecker) cpb.getRevocationChecker();
				rc.setOptions(EnumSet.of(PKIXRevocationChecker.Option.NO_FALLBACK));
				rc.setOcspResponder(new URI("http://localhost:9080"));  // Aqui poner la ip y puerto donde se haya lanzado el OCSP Responder

				//   2. Crear el truststore 
				
				KeyStore ts = KeyStore.getInstance("JCEKS");
				ts.load(new FileInputStream(raizMios + "trustStoreCliente.jce"), passphrase);
				
				//  3. Crear los parametros PKIX y el PKIXRevocationChecker
				
				PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(ts, new X509CertSelector());
				pkixParams.addCertPathChecker(rc);
				pkixParams.setRevocationEnabled(false); // habilitar la revocacion (por si acaso)
				
				//
				TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
				tmf.init(new CertPathTrustManagerParameters(pkixParams));
				

				// --- Key manager 
				
				kmf = KeyManagerFactory.getInstance("SunX509");
				ks = KeyStore.getInstance("JCEKS");
				ks.load(new FileInputStream(raizMios + "keyStoreCliente.jce"), passphrase);
				kmf.init(ks, passphrase);
				
				// Crear el contexto
				ctx = SSLContext.getInstance("TLS");		
				ctx.init(kmf.getKeyManagers(),  
						 null,//tmf.getTrustManagers(), 
						 null);
		
				factory = ctx.getSocketFactory();
				  
				
		
				// Suites disponibles		
			
		    	 System.out.println ("*****************************************************");
		    	 System.out.println ("*         CypherSuites Disponibles en CLIENTE        ");
		    	 System.out.println ("*****************************************************");
		    	 
		         String[]cipherSuites = factory.getSupportedCipherSuites();
	 	   	     for (int i=0; i<cipherSuites.length; i++) 
	 	       		System.out.println (cipherSuites[i]);	    
	 		   	    
	 	   	     // Suites habilitadas por defecto
	 	   	     
		    	 System.out.println ("*****************************************************");
		    	 System.out.println ("*         CypherSuites Habilitadas por defecto       ");
		    	 System.out.println ("*****************************************************");
		     	    
	 	   	     String[] cipherSuitesDef = factory.getDefaultCipherSuites();
	 	   	     for (int i=0; i<cipherSuitesDef.length; i++) 
	 	       		 System.out.println (cipherSuitesDef[i]);
	     
			} catch (Exception e) {
					throw new IOException(e.getMessage());}

		  SSLSocket socket = (SSLSocket)factory.createSocket("localhost", 9001);
		 
		  // Ver los protocolos
		  
	  	  System.out.println ("*****************************************************");
	  	  System.out.println ("*  Protocolos soportados en Cliente                 ");
	  	  System.out.println ("*****************************************************");

		  String[] protocols = socket.getEnabledProtocols();
		  for (int i=0; i<protocols.length; i++) 
		    	System.out.println (protocols[i]);	    
	  		
	  	  System.out.println ("*****************************************************");
	  	  System.out.println ("*    Protocolo forzado                               ");
	  	  System.out.println ("*****************************************************");
		 	
		  String[] protocolsNew = {"TLSv1.3"};	  
		
		  socket.setEnabledProtocols(protocolsNew);


		  System.out.println ("*****************************************************");
		  System.out.println ("*         CypherSuites  Disponibles (Factory)        ");
		  System.out.println ("*****************************************************");
	 
	      cipherSuitesDisponibles = factory.getSupportedCipherSuites();
	      for (int i=0; i<cipherSuitesDisponibles.length; i++) 
	 		  System.out.println (cipherSuitesDisponibles[i]);	    
	      
	      // Habilitar las suites deseadas
	      
	      String[]   cipherSuitesHabilitadas = {//"TLS_RSA_WITH_NULL_SHA256",
	    		                               //"TLS_ECDHE_RSA_WITH_NULL_SHA",
								    		  "TLS_AES_128_GCM_SHA256",
								    		  //"TLS_AES_256_GCM_SHA384",
								    		  //"TLS_CHACHA20_POLY1305_SHA256",
								    		  //"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
								    		  //"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
								    		  //"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
								    		  //"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
								    		  //"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
								    		  //"TLS_RSA_WITH_AES_256_GCM_SHA384",
								    		  //"TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
								    		  //"TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
								    		  //"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
								    		  //"TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
								    		  //"TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
								    		  //"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
								    		  //"TLS_RSA_WITH_AES_128_GCM_SHA256",
								    		  "TLS_RSA_WITH_AES_128_CBC_SHA256",
								    		  "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
								    		  "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
								    		  "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
								    		  "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
								    		  "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
								    		  "TLS_RSA_WITH_AES_128_GCM_SHA256",
								    		  "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
								    		  "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
								    		  "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
	  		  
	    		                               };	 
	     if (true)
	    	 socket.setEnabledCipherSuites(cipherSuitesHabilitadas);
	 	 
		 System.out.println ("*****************************************************");
		 System.out.println ("*         CypherSuites Habilitadas en socket         ");
		 System.out.println ("*****************************************************");
	     
	 	 String[] cipherSuitesHabilSocket = socket.getEnabledCipherSuites();
	  	 for (int i=0; i<cipherSuitesHabilSocket.length; i++) 
	 	       		System.out.println (cipherSuitesHabilSocket[i]);

	     socket.getSSLParameters().getUseCipherSuitesOrder();


		    /*
		     * send http request
		     *
		     * See SSLSocketClient.java for more information about why
		     * there is a forced handshake here when using PrintWriters.
		     */
		    
		    
		    System.out.println ("Comienzo SSL Handshake");
		    socket.startHandshake();	    
		    System.out.println ("Fin SSL Handshake");
		    //String s = socket.getHandshakeSession().getCipherSuite();
		    System.out.println ("*****************" + socket.getSession());
		    
		    ////////////////////////////////////////////////////////////////////
			
			//Flujos salientes para cabecera y datos  
			OutputStream streamSalida = socket.getOutputStream();
			// Flujo normal (texto) para la cabecera
			PrintWriter flujoCabecera = new PrintWriter(new BufferedWriter(new OutputStreamWriter(streamSalida)));
			// Flujo binario (object) para los datos 
			ObjectOutputStream flujoDatos = new ObjectOutputStream(streamSalida);
			
		   //Flujos entrantes para cabecera y datos  
			InputStream streamEntrada = socket.getInputStream();
			BufferedReader    flujoCabecera_E = new BufferedReader(new InputStreamReader(streamEntrada));
			ObjectInputStream flujoDatos_E    = new ObjectInputStream(streamEntrada);
			
			String inputLine = new String();
	
			int salir = 0;
			
			while(salir==0) {
				String opcion = menu();
				
				switch(opcion.toUpperCase()) {
					case "R" : 
						System.out.println("REGISTRAR UN DOCUMENTO\n");
						
						//Obtener certificadoAutenticacionCliente 
						X509Certificate certificadoAutenticacionCliente = (X509Certificate) ks.getCertificate("cert_cliente_rsa");
						byte[] certificadoAutClienteBytes = certificadoAutenticacionCliente.getEncoded();
						Principal idPropietario = certificadoAutenticacionCliente.getSubjectX500Principal();
						String id = idPropietario.getName();
						
						//Obterner nombre documento
						String nombreDocumento = "";
						do {
							System.out.print("Introduce el nombre del documento [0-100]: ");
							nombreDocumento = keyboard.nextLine();
						} while(nombreDocumento.length()>100) ;
						
						byte[] docBytes = null;
						docBytes = Crypto.getBytes(nombreDocumento);
						
						//Cifrar
						String documentoACifrar = path+nombreDocumento;
						/************************************************************
						 Generar y almacenar la clave 
						 ************************************************************/
						String claveCifradoSimetrico = pathCifrado+"clave"+nombreDocumento;
						FileOutputStream fclave = new FileOutputStream(claveCifradoSimetrico);
						
						// Generarla
						KeyGenerator kgen = KeyGenerator.getInstance(algoritmo);
						kgen.init(longclave);
						SecretKey skey = kgen.generateKey();
								
						// Almacenarla
						byte[] skey_raw = skey.getEncoded();
						fclave.write(skey_raw);
						fclave.close();
						
						// Leerla
						SecretKeySpec ks = new SecretKeySpec(skey_raw, algoritmo);
						
						//CIFRADO SIMETRICO
						byte [] cifradoSimetricoDocumento = CifradoSimetrico.cifradoDescrifradoSimetricoPrincipal(documentoACifrar,"cifrar",ks);
						byte [] parametrosCifradoSimetrico = CifradoSimetrico.obtenerParametros();
						
						//CIFRADO ASIMETRICO DE LA CLAVE KS
						 //Leer la clave public del servidor del trustsotreclienteaplicacion
						//Para descifrar sacamos la privada del keystore del servidor
						
						//byte [] cifradoAsimetricoClave = CifradoDescrifradoAsimetrico.cifradoDescrifradoAsimetricoPrincipal(claveCifradoSimetrico,"cifrar",keypar);
						//byte [] cifradoAsimetricoClave = new byte[1024];
						
						//FIRMA
						byte[] firmaDocumento = FirmaAsimetricaKeyStore.firmaAsimetrica(nombreDocumento, id);
						
						//Certificado de clave publica de firma del propietario
						byte[] certificadoFirma = certificadoAutenticacionCliente.getEncoded();
						
						//Guardamos en el mapa el documento y su firma hasta la respuesta del servidor
						archivosCliente.put(nombreDocumento,firmaDocumento);
						 
						/*MensajeRegistrar_Request mensajeRegistro = new MensajeRegistrar_Request(certificadoAutClienteBytes,nombreDocumento,
								cifradoAsimetricoClave,cifradoSimetricoDocumento,firmaDocumento,certificadoFirma,parametrosCifradoSimetrico);*/
						byte [] a = new byte[1024];
						MensajeRegistrar_Request mensajeRegistro = new MensajeRegistrar_Request(a,nombreDocumento,a,a,a,a,a);
						
						// enviar cabecera
						flujoCabecera.println("REGISTRAR");
						flujoCabecera.flush();
						// envíar  datos
						flujoDatos.writeObject(mensajeRegistro);
						flujoDatos.flush();
						
						/*  
						 * ENVIAMOS MENSAJE REQUEST AL SERVIDOR
						 * */
						
						
						// Leer Respuesta 
					   
					    inputLine = flujoCabecera_E.readLine();
					    MensajaRegistrar_Response mensajeRespuesta = (MensajaRegistrar_Response) flujoDatos_E.readObject();
					    //MensajaRegistrar_Response.response(mensajeRespuesta);
					    
					    if(mensajeRespuesta.getNumeroError()!=0) {
					    	//decimos que tipo de error
					    }else {
					    	System.out.println("RESPUESTA CORRECTA\n");
					    	byte[] certFirmaA = mensajeRespuesta.getCertificadoFirmas();
					    	//Comparamos con el certificado guardado en el trustsotre
					    	
					    	/* */
					    	
					    	
					    	byte[] sigRD = mensajeRespuesta.getFirmaRegistrador();
					    	byte[] idPropietarioRespuesta = mensajeRespuesta.getIdPropietario();
					    	String idPropietarioRespuestaString = new String(idPropietarioRespuesta, StandardCharsets.UTF_8);
					    	boolean verFirma = FirmaAsimetricaKeyStore.verificacionAsimetrica(nombreDocumento,sigRD,idPropietarioRespuestaString);
					    	if(verFirma) {
					    		//Computar y almacenar el hash
					    		System.out.println("Documento registrado correctamente con: "+mensajeRespuesta.getIdRegistro());
					    		MessageDigest dig = MessageDigest.getInstance("SHA-256");
					    		byte[] hash = dig.digest(docBytes);
					    		hashRespuestaServidor.put(mensajeRespuesta.getIdRegistro(), hash);
					    		//Borrar el documento enviado y la firma
					    		archivosCliente.remove(firmaDocumento);
					    	}
					    }
					    					    						
						break;
						
					case "O" : 
						System.out.println("RECUPERAR DOCUMENTO\n");
						/*
						//Obtener certificadoAutenticacionCliente 
						X509Certificate certificadoAutClienteRespuesta = (X509Certificate) ks.getCertificate("cert_cliente_rsa");
						byte[] certificadoAutClienteRespuestaBytes = certificadoAutenticacionCliente.getEncoded();
						Principal idPropietarioRespuesta = certificadoAutClienteRespuesta.getSubjectX500Principal();
						String idRespuesta = idPropietarioRespuesta.getName(); */
						
						
						RecuperarDocumento_Request documentoRecuperar = RecuperarDocumento_Request.recuperar();
						// enviar cabecera
						flujoCabecera.println("RECUPERAR");
						flujoCabecera.flush();
						// envíar  datos
						flujoDatos.writeObject(documentoRecuperar);
						flujoDatos.flush();
						
						// Leer Respuesta 
	
	
					    inputLine = flujoCabecera_E.readLine();
					    RecuperarDocumento_Response documentoRespuesta = (RecuperarDocumento_Response) flujoDatos_E.readObject();
				
					    RecuperarDocumento_Response.response(documentoRespuesta);
						
						break;
						
					case "X" :
						salir=1;
						break;	
						
				}
			}
			
		} catch(SocketException e) {
			System.out.println("Socket Exception");
		} catch(IOException e1) {
			System.out.println("IOException");
		} catch(Exception e2) {
			System.out.println("Excepcion genérica");
		}
		
		
	}
	
	static String menu() {
		System.out.println("Introduce el servicio al que quieres acceder \n"
				+ "-Registrar un documento [R]\n"
				+ "-Recuperar un documento [O]\n"
				+ "-Salir del programa [X]");
		
		
		return (keyboard.nextLine());
		
	}
	
	private static void definirAlmacenesCliente()
	{
		String 	raizMios     = "/home/miguel/SEG/";

		// Almacen de claves
		
		System.setProperty("javax.net.ssl.keyStore",            raizMios + "keyStoreCliente.jce");
		System.setProperty("javax.net.ssl.keyStoreType",       "JCEKS");
		System.setProperty("javax.net.ssl.keyStorePassword",   "1234");

		// Almacen de confianza
		
		System.setProperty("javax.net.ssl.trustStore",          raizMios + "trustStoreCliente.jce");		
		System.setProperty("javax.net.ssl.trustStoreType",     "JCEKS");
		System.setProperty("javax.net.ssl.trustStorePassword", "1234");

	}
    
   /* private static void definirRevocacionOCSP()
	{

		// Almacen de claves
		
		System.setProperty("com.sun.net.ssl.checkRevocation",        "true");
		System.setProperty("ocsp.enable",                            "true");

	}*/
    
    private static void definirRevocacionOCSPStapling()
	{

		// Almacen de claves
		
		System.setProperty("jdk.tls.client.enableStatusRequestExtension",   "true");
		System.setProperty("com.sun.net.ssl.checkRevocation",        "true");
		System.setProperty("ocsp.enable",                            "false");
		System.out.println("propiedad="+System.getProperty("jdk.tls.client.enableStatusRequestExtension"));

	}
		
}

