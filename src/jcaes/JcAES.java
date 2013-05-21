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
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
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

	final static byte RSA_ENCRYPT = (byte) 0x07;
	final static byte RSA_DECRYPT = (byte) 0x08;
	final static byte EXPORT_RSA_EXP = (byte) 0x09;
	final static byte EXPORT_RSA_MOD = (byte) 0x10;

	final static byte IMPORT_CERT = (byte) 0x11;
	final static byte EXPORT_CERT = (byte) 0x12;
	final static byte GET_CERT_LEN = (byte) 0x13;
	final static byte IMPORT_PRIVATE_EXP = (byte)0x14;
	final static byte IMPORT_MODULUS = (byte)0x15;
	final static byte IMPORT_PUBLIC_EXP = (byte)0x16;

	//secret key
	final static byte[] _aesKey = {(byte) 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
	final static byte[] _desKey = {(byte) 0x02,0x02,0x03,0x04,0x05,0x06,0x07,0x08};

	byte[] dataToEncrypt;
	byte[] dataToDecrypt;
	byte[] result;

	KeyPair _rsaKeyPair;
	Signature _signature;

	Cipher rsaCipher;
	byte[] rsaEncrypted,rsaDecrypted;
	byte[] exponent,modulus;

	byte[] certificate;
	short cert_len;
	short cert_block_size = 120;
	RSAPrivateKey _rsaPrivKey = null;
	RSAPublicKey _rsaPubKey = null;

	byte[] reply = null;



	public static void install(byte[] buffer, short offset, byte length) {
		new JcAES();
	}

	private JcAES(){
		//allocate all memory
		dataToEncrypt = new byte[64];
		dataToDecrypt = new byte[64];
		result = new byte[64];

		//KeyAgreement dhKeyAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
		_rsaKeyPair = new KeyPair(KeyPair.ALG_RSA, (short) 512);
		_rsaKeyPair.genKeyPair();

		_rsaPrivKey = (RSAPrivateKey) _rsaKeyPair.getPrivate();
		_rsaPubKey = (RSAPublicKey) _rsaKeyPair.getPublic();

		//dhKeyAgreement.init(_rsaKeyPair.getPrivate());
		//_signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);

		//rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
		rsaEncrypted = new byte[64];
		rsaDecrypted = new byte[64];
		//exponent = new byte[16];
		//modulus = new byte[64];

		certificate = new byte[1024];
		cert_len = 0;

		reply = new byte[256];




		register();
	}

	public void process(APDU apdu) throws ISOException {

		if (selectingApplet()) {//select command	
			return;
		}

		byte[] cmd = apdu.getBuffer();

		for(byte i=0;i<16;i++)
			result[i]=0;

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
				_signature.init(_rsaPrivKey, Signature.MODE_SIGN);
				byte[] test = {1,2,3,4,5};
				byte[] test_signature = new byte[64];//generate 64 byte signature
				_signature.sign(test, (short)0	, (short)test.length, test_signature, (short)0);

				apdu.setOutgoing();            
				apdu.setOutgoingLength((short)test_signature.length);
				apdu.sendBytesLong(test_signature, (short)0, (short)test_signature.length);
				break;
			case RSA_ENCRYPT:
				data_len = (short)(cmd[ISO7816.OFFSET_LC] & 0x00FF);
				rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
				rsaCipher.init(_rsaPubKey, Cipher.MODE_ENCRYPT);
				Util.arrayCopy(cmd, ISO7816.OFFSET_CDATA, dataToEncrypt, (short) 0, data_len);
				short number_bytes = rsaCipher.doFinal(dataToEncrypt, (byte)0, data_len, rsaEncrypted, (byte)0);

				apdu.setOutgoing();
				apdu.setOutgoingLength(number_bytes);
				apdu.sendBytesLong(rsaEncrypted, (short)0, number_bytes);
				break;

			case RSA_DECRYPT:
				data_len = (short)(cmd[ISO7816.OFFSET_LC] & 0x00FF);
				rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
				rsaCipher.init(_rsaPrivKey, Cipher.MODE_DECRYPT);
				Util.arrayCopy(cmd, ISO7816.OFFSET_CDATA, dataToDecrypt, (short) 0, data_len);
				number_bytes = rsaCipher.doFinal(dataToDecrypt, (byte)0, (short)64, rsaDecrypted, (byte)0);

				apdu.setOutgoing();
				apdu.setOutgoingLength(number_bytes);
				apdu.sendBytesLong(rsaDecrypted, (short)0, number_bytes);
				break;

			case EXPORT_RSA_EXP:
				try{
					_rsaPrivKey.getExponent(cmd, (short) 0);

					apdu.setOutgoing();
					apdu.setOutgoingLength((short)64);
					apdu.sendBytesLong(cmd, (short)0, (short)64);
				}catch(Exception e){
					ISOException.throwIt(ISO7816.SW_DATA_INVALID);
				}
				break;

			case EXPORT_RSA_MOD:
				try{
					_rsaPrivKey.getModulus(reply, (short) 0);


					apdu.setOutgoing();
					apdu.setOutgoingLength((short)64);
					apdu.sendBytesLong(reply, (short)0, (short)64);
				}catch(Exception e){
					ISOException.throwIt(ISO7816.SW_DATA_INVALID);
				}
				break;

			case IMPORT_CERT:
				data_len = 0;
				byte blocknumber = cmd[ISO7816.OFFSET_P1];
				try{
					data_len = (short)(cmd[ISO7816.OFFSET_LC] & 0x00FF);


					if(blocknumber == 0)
						cert_len = 0;
					cert_len += data_len;
					//cert_len = (short) (cert_len+(short)1);
					Util.arrayCopy(cmd, ISO7816.OFFSET_CDATA, certificate, (short) (blocknumber*cert_block_size), data_len);
				}catch(Exception e){
					ISOException.throwIt(ISO7816.SW_DATA_INVALID);
				}
				short le = apdu.setOutgoing();
				//if ( le < 2 )
				//	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

				apdu.setOutgoingLength((short)2);
				cmd[0] = (byte) (data_len>>8);
				cmd[1] = (byte) (data_len & 0x00ff);
				apdu.sendBytesLong(cmd, (short)0, (short)2);
				break;

			case EXPORT_CERT:
				try{
					blocknumber = cmd[ISO7816.OFFSET_P1];
					le = apdu.setOutgoing();

					apdu.setOutgoingLength(le);
					apdu.sendBytesLong(certificate, (short) (blocknumber*cert_block_size), (short)le);


				}catch(Exception e){
					ISOException.throwIt(ISO7816.SW_DATA_INVALID);
				}
				break;
			case GET_CERT_LEN:
				apdu.setOutgoing();
				apdu.setOutgoingLength((short)2);

				cmd[0] = (byte) (cert_len>>8);
				cmd[1] = (byte) (cert_len&0x00ff);
				apdu.sendBytesLong(cmd, (short)0, (short)2);
				break;

			case IMPORT_PRIVATE_EXP:
				data_len = (short)(cmd[ISO7816.OFFSET_LC] & 0x00FF);
				//_rsaPrivKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, (short) 512,true);
				_rsaPrivKey.setExponent(cmd, ISO7816.OFFSET_CDATA, (short) data_len);
				short bla = _rsaPrivKey.getSize();
				cmd[0] = (byte) (bla>>8);
				cmd[1] = (byte) ((byte) bla&0x00ff);
				apdu.setOutgoing();
				apdu.setOutgoingLength((short)2);
				apdu.sendBytesLong(cmd, (short)0, (short)2);
				break;
			case IMPORT_PUBLIC_EXP:
				data_len = (short)(cmd[ISO7816.OFFSET_LC] & 0x00FF);
				//_rsaPubKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, (short) 512,true);
				_rsaPubKey.setExponent(cmd, ISO7816.OFFSET_CDATA, (short) data_len);
				bla = _rsaPubKey.getSize();
				cmd[0] = (byte) (bla>>8);
				cmd[1] = (byte) ((byte) bla&0x00ff);
				apdu.setOutgoing();
				apdu.setOutgoingLength((short)2);
				apdu.sendBytesLong(cmd, (short)0, (short)2);
				break;
			case IMPORT_MODULUS:
				data_len = (short)(cmd[ISO7816.OFFSET_LC] & 0x00FF);
				_rsaPubKey.setModulus(cmd, ISO7816.OFFSET_CDATA, (short) data_len);
				_rsaPrivKey.setModulus(cmd, ISO7816.OFFSET_CDATA, (short) data_len);
				cmd[0] = 00;
				cmd[1] = 01;
				apdu.setOutgoing();
				apdu.setOutgoingLength((short)2);
				apdu.sendBytesLong(cmd, (short)0, (short)2);
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
