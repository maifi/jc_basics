package jcaes;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.Key;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

public class JcAES extends Applet {

	final static byte CLASS  = (byte) 0x00;
	final static byte ENCRYPT  = (byte) 0x01;
	final static byte DECRYPT  = (byte) 0x02;
	final static byte ENCRYPT_DES  = (byte) 0x03;
	final static byte DECRYPT_DES  = (byte) 0x04;
	
	final static byte SIGN_DATA = (byte) 0x05;
	final static byte GET_PUBLIC_KEY = (byte) 0x06;
	
	//secret key
	final static byte[] _aesKey = {(byte) 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
	final static byte[] _desKey = {(byte) 0x02,0x02,0x03,0x04,0x05,0x06,0x07,0x08};

	byte[] dataToEncrypt;
	byte[] dataToDecrypt;
	byte[] result;
	
	KeyPair _rsaKeyPair;
	Signature _signature;
	
	
	public static void install(byte[] buffer, short offset, byte length) {
		new JcAES();
	}
	
	private JcAES(){
		//allocate all memory
		dataToEncrypt = new byte[16];
		dataToDecrypt = new byte[16];
		result = new byte[16];
		
		//KeyAgreement dhKeyAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
		_rsaKeyPair = new KeyPair(KeyPair.ALG_RSA, (short) 512);
		_rsaKeyPair.genKeyPair();
		
		//dhKeyAgreement.init(_rsaKeyPair.getPrivate());
		_signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);

		register();
	}

	public void process(APDU apdu) throws ISOException {
		
		if (selectingApplet()) {//select command	
			return;
		}
		
		byte[] cmd = apdu.getBuffer();
		
	    if (cmd[ISO7816.OFFSET_CLA] == CLASS) {  
	    	switch(cmd[ISO7816.OFFSET_INS]) {      
	        	case ENCRYPT:
	        		//we dont care of P1 and P2 now
	        		short data_len = (short)(cmd[ISO7816.OFFSET_LC] & 0x00FF);//must be 16
	
	        		Util.arrayCopy(cmd, ISO7816.OFFSET_CDATA, dataToEncrypt, (short) 0, data_len);
	        		
	        		result = aesEncrypt(dataToEncrypt);
	        		
		            apdu.setOutgoing();            
		            apdu.setOutgoingLength((short)result.length);
		            apdu.sendBytesLong(result, (short)0, (short)result.length);
	        		break;
	        		
	        	case DECRYPT:
	        		data_len = (short)(cmd[ISO7816.OFFSET_LC] & 0x00FF);
	        		byte[] decryptedData;
	        		Util.arrayCopy(cmd, ISO7816.OFFSET_CDATA, dataToDecrypt, (short) 0, data_len);
	        		
	        		decryptedData = aesDecrypt(dataToDecrypt);
	        		
		            apdu.setOutgoing();            
		            apdu.setOutgoingLength((short)decryptedData.length);
		            apdu.sendBytesLong(decryptedData, (short)0, (short)decryptedData.length);
		            break;
		            
	        	case ENCRYPT_DES:
	        		//we dont care of P1 and P2 now
	        		data_len = (short)(cmd[ISO7816.OFFSET_LC] & 0x00FF);
	        		Util.arrayCopy(cmd, ISO7816.OFFSET_CDATA, dataToEncrypt, (short) 0, data_len);
	        		
	        		result = desEncrypt(dataToEncrypt);
	        		
		            apdu.setOutgoing();            
		            apdu.setOutgoingLength((short)result.length);
		            apdu.sendBytesLong(result, (short)0, (short)result.length);
	        		break;
	        		
	        	case DECRYPT_DES:
	        		data_len = (short)(cmd[ISO7816.OFFSET_LC] & 0x00FF);
	        		Util.arrayCopy(cmd, ISO7816.OFFSET_CDATA, dataToDecrypt, (short) 0, data_len);
	        		
	        		decryptedData = desDecrypt(dataToDecrypt);
	        		
		            apdu.setOutgoing();            
		            apdu.setOutgoingLength((short)decryptedData.length);
		            apdu.sendBytesLong(decryptedData, (short)0, (short)decryptedData.length);
		            break;
		            //SIGN data
	        	case SIGN_DATA:
	        		_signature.init(_rsaKeyPair.getPrivate(), Signature.MODE_SIGN);
	        		byte[] test = {1,2,3,4,5};
	        		byte[] test_signature = new byte[64];//generate 64 byte signature
	        		_signature.sign(test, (short)0	, (short)test.length, test_signature, (short)0);

		            apdu.setOutgoing();            
		            apdu.setOutgoingLength((short)test_signature.length);
		            apdu.sendBytesLong(test_signature, (short)0, (short)test_signature.length);
		            break;
	        	default:
	        		ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
	        } 
	      }  
	      else {         
	        ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
	      }  
		
	} 
	
	private byte[] aesEncrypt(byte[] data){
		
		try{
		Cipher cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD,false);
		AESKey aeskey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
		aeskey.setKey(_aesKey, (short) 0);

		cipher.init((Key)aeskey, Cipher.MODE_ENCRYPT);// error here!

		cipher.doFinal(data, (short) 0, (byte) data.length, result, (short) 0);
		return result;
		}catch(CryptoException c){

		}catch(Exception e){

		}
		return null;
	}
	
	private byte[] aesDecrypt(byte[] data){
		
		try{
		Cipher cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD,false);
		AESKey aeskey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
		aeskey.setKey(_aesKey, (short) 0);
		cipher.getAlgorithm();
		cipher.init((Key)aeskey, Cipher.MODE_DECRYPT);

		cipher.doFinal(data, (short) 0, (byte) result.length, result, (short) 0);
		return result;
		}catch(Exception e){

		}
		return null;
	}
	
private byte[] desEncrypt(byte[] data){
		
		try{
		Cipher cipher = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD,false);
		DESKey deskey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);
		deskey.setKey(_desKey, (short) 0);

		cipher.init((Key)deskey, Cipher.MODE_ENCRYPT);

		cipher.doFinal(data, (short) 0, (byte) data.length, result, (short) 0);
		return result;
		}catch(CryptoException c){

		}catch(Exception e){

		}
		return null;
	}

	private byte[] desDecrypt(byte[] data){
		
		try{
		Cipher cipher = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD,false);
		DESKey deskey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);
		deskey.setKey(_desKey, (short) 0);

		cipher.init((Key)deskey, Cipher.MODE_DECRYPT);
		//cipher.update(data, (short) 0, (byte) 0x08, result, (short) 0);
		cipher.doFinal(data, (short) 0, (byte) 0x08, result, (short) 0);
		return result;
		}catch(Exception e){

		}
		return null;
	}
	
}
