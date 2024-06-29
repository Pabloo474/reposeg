package PrincipalSinOCSP;

import java.io.*;
import java.net.*;
import java.security.KeyStore;
import java.security.cert.CertPathBuilder;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509CertSelector;
import java.util.EnumSet;

import javax.net.*;
import javax.net.ssl.*;

/* ClassFileServer.java -- a simple file server that can server
 * Http get request in both clear and secure channel
 *
 * The ClassFileServer implements a ClassServer that
 * reads files from the file system. See the
 * doc for the "Main" method for how to run this
 * server.
 */

public class Servidor extends ClassServer {

    private String docroot;

    private static int      DefaultServerPort = 9001;
	private static String 	raizMios     = "/home/miguel/SEG/";
	private static KeyStore keyStore;
	private static KeyStore trustStore;
	
	static String keyStoreFile = new String();
	static String passwordKeyStore = new String();
	static String truststoreFile = new String();
	static String IpOCSPResponder = new String();

    /**
     * Constructs a ClassFileServer.
     *
     * @param path the path where the server locates files
     */
    public Servidor(ServerSocket ss,KeyStore keyStore,KeyStore trustStore) throws IOException
    {
		super(ss,keyStore,trustStore);
    }
    /**
     * Main method to create the class server that reads
     * files. This takes two command line arguments, the
     * port on which the server accepts requests and the
     * root of the path. To start up the server: <br><br>
     *
     * <code>   java ClassFileServer <port> <path>
     * </code><br><br>
     *
     * <code>   new ClassFileServer(port, docroot);
     * </code>
     */
    
    public static void main(String args[])
    {
   	String[]   cipherSuites = null;
   

	int port = DefaultServerPort;
	String docroot = "";

//  Chequear argumentos
	
	if (args.length != 4) {
		System.out.println("Los argumentos son : keyStoreFile contraseñaKeystore truststoreFile IpOCSPResponder");
		System.exit(-1);
	}
	
	keyStoreFile = args[0];
	passwordKeyStore = args[1];
	truststoreFile = args[2];
	IpOCSPResponder = args[3];
	
	//  Definir valores para los almacenes necesarios
	
	definirAlmacenesServidor(keyStoreFile,passwordKeyStore,truststoreFile);
	
	//  Definir las variables para establecer OCSP stapling
    	//  2 metodos: Probar primero con el metodo 1 y luego pasarse al metodo 2
	
	//definirRevocacionOCSPStapling_Metodo1();
	definirRevocacionOCSPStapling_Metodo2();
	
	
	
	try {
	    ServerSocketFactory ssf =
	    		Servidor.getServerSocketFactory("TLS");
	    
	    ServerSocket ss = ssf.createServerSocket(port);
	    
	    // Ver los protocolos
    	System.out.println ("*****************************************************");
    	System.out.println ("*  Protocolos soportados en Servidor                 ");
    	System.out.println ("*****************************************************");

	 	String[] protocols = ((SSLServerSocket)ss).getEnabledProtocols();
	 	for (int i=0; i<protocols.length; i++) 
	    	System.out.println (protocols[i]);	    
    		
    	System.out.println ("*****************************************************");
    	System.out.println ("*    Protocolo forzados                               ");
    	System.out.println ("*****************************************************");
	 	
	 	String[] protocolsNew = {"TLSv1.3"};
	 	
	 	((SSLServerSocket)ss).setEnabledProtocols(protocolsNew);
	 	
	 	//  volvemos a mostrarlos
	 	protocols = ((SSLServerSocket)ss).getEnabledProtocols();
	 	for (int i=0; i<protocols.length; i++) 
	    	System.out.println (protocols[i]);	    
    	
	    
	    //if (args.length >= 4 && args[3].equals("true")) {
	    
	    	System.out.println ("*****************************************************");
	    	System.out.println ("*  Server inicializado CON Autenticacion de cliente  ");
	    	System.out.println ("*****************************************************");

	    	// Ver Suites disponibles en Servidor
	    	
	    	System.out.println ("*****************************************************");
	    	System.out.println ("*         CypherSuites Disponibles en SERVIDOR       ");
	    	System.out.println ("*****************************************************");
	    	
		 	cipherSuites = ((SSLServerSocket)ss).getSupportedCipherSuites();
		 	for (int i=0; i<cipherSuites.length; i++) 
		    	System.out.println (i + "--" + cipherSuites[i]);	    
	    	
		 	//  Definir suites Habilitadas en server
		 	
		 	((SSLServerSocket)ss).setNeedClientAuth(true);
		 	
	        String[]   cipherSuitesHabilitadas = {"TLS_RSA_WITH_NULL_SHA256",
	        		                              "TLS_ECDHE_RSA_WITH_NULL_SHA",
	        		                               //TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	        		                              //"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	        		                              };

	        if (false) // cambiar a true para cambiarlas
	        	((SSLServerSocket)ss).setEnabledCipherSuites(cipherSuitesHabilitadas);
	        
	    	System.out.println ("*****************************************************");
	    	System.out.println ("*         CypherSuites Habilitadas en SERVIDOR       ");
	    	System.out.println ("*****************************************************");
	    
		 	cipherSuites = ((SSLServerSocket)ss).getEnabledCipherSuites();
		 	for (int i=0; i<cipherSuites.length; i++) 
		    	System.out.println (i + "--" + cipherSuites[i]);	    
	    	
	    //}
	    
	    new Servidor(ss, keyStore, trustStore);

	} catch (IOException e) {
	    System.out.println("Unable to start ClassServer: " +
			       e.getMessage());
	    e.printStackTrace();
	}
    }

    private static ServerSocketFactory getServerSocketFactory(String type) {
	
    if (type.equals("TLS")) {
    	
    	
	    SSLServerSocketFactory ssf = null;

	    try {
	    	
	    	//definirRevocacionOCSPStapling_Metodo1();
	    	definirRevocacionOCSPStapling_Metodo2();
  			/********************************************************************************
			*   Construir un contexto, pasandole el KeyManager y y TrustManager 
			*   Al TrustManager se le incorpora el chequeo de certificados revocados por Ocsp. 
			*   
			*   NOTA: Esto seria necesario para la verificacion de no-revocacion OCSP
			*   del certificado del cliente
			*   
			********************************************************************************/
	    	// set up key manager to do server authentication

			
			// --- Trust manager.
			
			//  1. Crear PKIXRevocationChecker
			CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX");
			PKIXRevocationChecker rc = (PKIXRevocationChecker) cpb.getRevocationChecker();
			rc.setOptions(EnumSet.of(PKIXRevocationChecker.Option.NO_FALLBACK));
			rc.setOcspResponder(new URI(IpOCSPResponder));  // Aqui poner la ip y puerto donde se haya lanzado el OCSP Responder


			//   2. Crear el truststore 
			char[] passphrase = "1234".toCharArray();
			KeyStore ts = KeyStore.getInstance("JCEKS");
			ts.load(new FileInputStream(raizMios + truststoreFile), passphrase);
			
			//  3. Crear los parametros PKIX y el PKIXRevocationChecker
			
			PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(ts, new X509CertSelector());
			//pkixParams.addCertPathChecker(rc);
			pkixParams.setRevocationEnabled(true); // habilitar la revocacion (por si acaso)
			
			//
			TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			tmf.init(new CertPathTrustManagerParameters(pkixParams));
			
	    	// set up key manager to do server authentication

			KeyManagerFactory kmf;
			KeyStore ks;
	
			// --- Key manager 

			kmf = KeyManagerFactory.getInstance("SunX509");
			ks = KeyStore.getInstance("JCEKS");	
			ks.load(new FileInputStream(raizMios + keyStoreFile), passwordKeyStore.toCharArray());
			//ks.load(new FileInputStream(raizMios + "serverKeystore.jceks"), passphrase);
			kmf.init(ks, passphrase);
		
			// Crear el contexto
			SSLContext ctx;
			ctx = SSLContext.getInstance("TLS");		
			ctx.init(kmf.getKeyManagers(),  
					 null,//tmf.getTrustManagers(), --solo si se hace el OCSP del certificado del cliente
					 null);
			
			ssf = ctx.getServerSocketFactory();
			return ssf;
			
	    } catch (Exception e) {
					e.printStackTrace();
				    }
	} else {
	    return ServerSocketFactory.getDefault();
	}
	return null;
    }




    private static void definirAlmacenesServidor(String keyStoreFile,String passwordKeyStore, String truststoreFile)
	{

		// Almacen de claves
    	System.out.println("Vamos a definir el trustStore y keyStore");
		
		System.setProperty("javax.net.ssl.keyStore",         raizMios + keyStoreFile);
		System.setProperty("javax.net.ssl.keyStoreType",     "JCEKS");
		System.setProperty("javax.net.ssl.keyStorePassword", passwordKeyStore);

		// Almacen de confianza
		System.setProperty("javax.net.ssl.trustStore",          raizMios + truststoreFile);		
		System.setProperty("javax.net.ssl.trustStoreType",     "JCEKS");
		System.setProperty("javax.net.ssl.trustStorePassword", "1234");

	}

    private static void definirRevocacionOCSPStapling_Metodo1()
	{
    	//
    	//  Metodo 1: Con URL en el campo AIA del certificado del servidor
    	//
    	    	
	    	System.setProperty("jdk.tls.server.enableStatusRequestExtension", "true");
		System.setProperty("jdk.tls.stapling.responderOverride","false");
	

	//  Cambios en el certificado del servidor:
	//      En la seccion [server_ext] del fichero root-ca.conf), añadir la siguiente linea
	//  
        //      authorityInfoAccess= OCSP; URI:http://localhost:9080
	//
        //   Luego volver a firmar el certificado e importarlo al keyStore del server

	}

    private static void definirRevocacionOCSPStapling_Metodo2()
	{    		    
    	//
    	//  Metodo 2: Con URL en el codigo java del server  (aqui)
    	//
    
    		System.setProperty("jdk.tls.server.enableStatusRequestExtension", "true");
	  	System.setProperty("jdk.tls.stapling.responderOverride","true");
		System.setProperty("jdk.tls.stapling.responderURI", IpOCSPResponder);		
		System.setProperty("jdk.tls.stapling.ignoreExtensions", "true");
	}
}