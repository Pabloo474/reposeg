package PrincipalSinOCSP;


import java.io.*;
import java.net.*;
import java.security.KeyStore;

import Mensajes.*;


/************************************************************
 * ClassServer.java -- a simple file server that can serve
 * Http get request in both clear and secure channel
 *
 *  Basado en ClassServer.java del tutorial/rmi
 ************************************************************/
public abstract class ClassServer implements Runnable {

    private ServerSocket server = null;
    private KeyStore keyStore;
	private KeyStore trustStore;

    /**
     * Constructs a ClassServer based on <b>ss</b> and
     * obtains a file's bytecodes using the method <b>getBytes</b>.
     *
     */
    protected ClassServer(ServerSocket ss,KeyStore keyStoreServer, KeyStore trustStoreServer)
    {
    		server = ss;
    		keyStore = keyStoreServer;
    		trustStore = trustStoreServer;
    		newListener();
    }

    /***************************************************************
     * run() -- The "listen" thread that accepts a connection to the
     * server, parses the header to obtain the file name
     * and sends back the bytes for the file (or error
     * if the file is not found or the response was malformed).
     **************************************************************/
    public void run()
    {
		Socket socket;
	
		// accept a connection
		try 
		{
		    socket = server.accept();
		    System.out.println("Nuevo cliente\n");
	
		} 
		catch (IOException e) {
		    System.out.println("Class Server died: " + e.getMessage());
		    e.printStackTrace();
		    return;
		}
	
		// create a new thread to accept the next connection
		newListener();

		try 
		{		    
		    
			InputStream streamEntrada = socket.getInputStream();
			BufferedReader    flujoCabecera_E = new BufferedReader(new InputStreamReader(streamEntrada));
			ObjectInputStream flujoDatos_E    = new ObjectInputStream(streamEntrada);
			
			String accion = flujoCabecera_E.readLine(); //REGISTRAR
			if(accion.equals("REGISTRAR")) {
				MensajeRegistrar_Request mensajeRegistrar = (MensajeRegistrar_Request) flujoDatos_E.readObject(); //OBJETO
				registrar(mensajeRegistrar);
			}else if(accion.equals("RECUPERAR")){
				RecuperarDocumento_Request mensajeRecuperar = (RecuperarDocumento_Request) flujoDatos_E.readObject(); //OBJETO
			}
				    
	
		} catch (Exception ex) {
		    // eat exception (could log error to log file, but
		    // write out to stdout for now).
		    System.out.println("error writing response: " + ex.getMessage());
		    ex.printStackTrace();
	
		} finally {
		    try {
			socket.close();
		    } catch (IOException e) {
		    }
		}
    }

    /********************************************************
     * newListener()
     * 			Create a new thread to listen.
     *******************************************************/
    private void newListener()
    {
    	(new Thread(this)).start();
    }
      
      private static void registrar(MensajeRegistrar_Request Request) {
    	  System.out.println("Registrando documento\n");
    	  System.out.println("El nombre del documento es: "+Request.getNombreDoc());
      }
}

