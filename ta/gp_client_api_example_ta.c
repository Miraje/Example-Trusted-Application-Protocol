#define STR_TRACE_USER_TA "GP_CLIENT_API_EXAMPLE"

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include "ta_gp_client_api_example.h"

/* Session data */
typedef struct session_data{
	TEE_OperationHandle *cipher_op;
	TEE_OperationHandle *digest_op;
}Session_data;


static void dump_hash(char *hash, size_t len)
{
	size_t i;

	IMSG("------------------------------------------------------ DUMPING HASH -----------------------------------------------------------\n");

	for (i = 0; i < len; i++)
		IMSG("%02x", hash[i]);

	IMSG("-------------------------------------------------------------------------------------------------------------------------------\n");
}


TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called.");
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	DMSG("has been called.");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param  params[4], void **sess_ctx)
{	
	Session_data * data;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;

	data = TEE_Malloc(sizeof(Session_data), 0);
	data->cipher_op = TEE_Malloc(sizeof(TEE_OperationHandle), 0);
	data->digest_op = TEE_Malloc(sizeof(TEE_OperationHandle), 0);

	*sess_ctx = data;

	DMSG("Has been called (session opened with the TA)");

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	DMSG("has been called (session with the TA will be closed.)");

	TEE_Free(((Session_data *)sess_ctx)->cipher_op);
	TEE_Free(((Session_data *)sess_ctx)->digest_op);
	TEE_Free(sess_ctx);	
}

static TEE_Result cipher_operation(TEE_OperationHandle crypto_op, TEE_ObjectHandle key, TEE_OperationMode mode, void * IV, size_t IVlen, uint32_t algorithm, void * srcData, size_t srcLen, void * destData, size_t * destLen)
{
	/* Return */
	TEE_Result result = TEE_SUCCESS;
		
	/* Cipher process */
	TEE_ObjectInfo keyInfo;
	size_t writen_bytes = 0;
	size_t remaining_bytes = 0;

	IMSG("-------------------------------------------------- CIPHER OPERATION ----------------------------------------------------------\n");

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */
	/* Get key object info */	
	TEE_GetObjectInfo(key, &keyInfo);

	IMSG("Key Info - objectType: %x, objectUsage:  %x, objectSize: %d, maxObjectSize: %d, handleFlags:%x, datasize: %d, dataposition: %d\n", keyInfo.objectType, keyInfo.objectUsage, keyInfo.objectSize, keyInfo.maxObjectSize, keyInfo.handleFlags, keyInfo.dataSize, keyInfo.dataPosition);

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */
	/* Allocate a handle for a new cryptographic operation */
	result = TEE_AllocateOperation(&crypto_op, algorithm, mode, keyInfo.maxObjectSize);

	if (result != TEE_SUCCESS) {
		IMSG("Failed to allocate an operation: 0x%x", result);
		goto cleanup1;
	}

	IMSG("Cryptographic operation allocated with success.\n");

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */
	/* Program the key of the operation */
	result = TEE_SetOperationKey(crypto_op, key);

	if (result != TEE_SUCCESS) {
		IMSG("Failed to set operation key: 0x%x", result);
		goto cleanup2;
	}

	IMSG("Key for cryptographic operation set with success.\n");

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */	
	/* Start the symmetric cipher operation */
	TEE_CipherInit(crypto_op, IV, IVlen);

	IMSG("Cipher operation initiated with success.\n");

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */
	/* Encrypt or decrypt the input data */
	
	writen_bytes = *destLen;

	result = TEE_CipherUpdate(crypto_op, srcData, srcLen, destData, &writen_bytes);

	if (result != TEE_SUCCESS) {
		IMSG("Cipher operation Update failed : 0x%x", result);
		goto cleanup2;
	}	

	IMSG("Cipher operation updated with success (bytes written: %zu).\n", writen_bytes);

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */
	/* Finalize the cipher operation */
	remaining_bytes = *destLen - writen_bytes;

	result = TEE_CipherDoFinal(crypto_op, (void *)NULL, 0, (unsigned char *)destData + writen_bytes, &remaining_bytes);

	if (result != TEE_SUCCESS) {
		IMSG("Cipher operation Do final failed : 0x%x", result);
		goto cleanup2;
	}

	IMSG("Cipher operation finalized with success (remaining bytes: %zu).\n", remaining_bytes);

	*destLen = writen_bytes + remaining_bytes;

	IMSG("Cipher operation: destination total number of bytes: %zu.\n", *destLen);

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */	
	cleanup2:
		TEE_FreeOperation(crypto_op);
	cleanup1:
		IMSG("-------------------------------------------------------------------------------------------------------------------------------\n");
		return result;

}


static TEE_Result encrypt_operation(Session_data * session_data)
{
	/* Return */
	TEE_Result result = TEE_SUCCESS;
	
	/* Transient key */
	TEE_ObjectHandle transient_key =  TEE_HANDLE_NULL;
	TEE_ObjectInfo keyInfo;
	uint32_t keyType = TEE_TYPE_AES;
	uint32_t keySize = 256;

	/* Peristent key */
	TEE_ObjectHandle persistent_key = TEE_HANDLE_NULL;
	TEE_ObjectInfo keyInfo2;
	uint32_t objectID = 1;
	size_t objectIDLen = sizeof(objectID);

	/* Crypto Operation */
	uint32_t algorithm = TEE_ALG_AES_CTS;
	/*uint32_t mode = TEE_MODE_ENCRYPT;*/
	
	/* Cipher process */
	char srcData[] = "Miraje is the boss!";	
	void * void_srcData = NULL;
	void * destData = NULL;
	void * decipheredData = NULL;
	void * IV  = NULL;
	size_t srcLen = 19;
	size_t destLen = 32;				/* buffer that is at least 2*BLOCKSIZE to ensure all remaining bytes are retrieved in final */
	size_t decipheredLen = destLen;
	size_t IVlen = 16;

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */
	/* Allocate an uninitialized transient object */
	result = TEE_AllocateTransientObject(keyType, keySize, &transient_key);

	if (result != TEE_SUCCESS) {
		IMSG("Failed to Allocate transient object handle : 0x%x", result);
		goto cleanup1;
	}

	IMSG("Transient object for AES key allocated with success.\n");

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */
	/* Generate a random key and populates a transient key object with the generated key material */
	result = TEE_GenerateKey(transient_key, keySize, (TEE_Attribute *)NULL,  0);

	if (result != TEE_SUCCESS) {
		IMSG("Failed to generate a transient key: 0x%x", result);
		TEE_FreeTransientObject(transient_key);
		goto cleanup1;
	}

	IMSG("AES-256 key generated with success.\n");

	TEE_GetObjectInfo(transient_key, &keyInfo);

	IMSG("Transient Key Info - objectType: %x, objectUsage:  %x, objectSize: %d, maxObjectSize: %d, handleFlags:%x, datasize: %d, dataposition: %d\n", keyInfo.objectType, keyInfo.objectUsage, keyInfo.objectSize, keyInfo.maxObjectSize, keyInfo.handleFlags, keyInfo.dataSize, keyInfo.dataPosition);

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */
	/* Create a persistent object with initial attributes  and return a handle on the created object (or not) */

	result = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, &objectID, objectIDLen, TEE_DATA_FLAG_ACCESS_WRITE  | TEE_DATA_FLAG_ACCESS_WRITE_META , transient_key, NULL, 0, NULL);

	if (result != TEE_SUCCESS) {
		IMSG("Failed to create a persistent key: 0x%x", result);
		TEE_FreeTransientObject(transient_key);
		goto cleanup1;
	}

	IMSG("Persistent object for AES key allocated with success.\n");

	TEE_FreeTransientObject(transient_key);

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */
	/* Open a handle on an existing persistent object */

	result = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, &objectID, objectIDLen,  TEE_DATA_FLAG_ACCESS_READ, &persistent_key);

	if (result != TEE_SUCCESS) {
		IMSG("Failed to open persistent key: 0x%x", result);
		goto cleanup1;
	}

	TEE_GetObjectInfo(persistent_key, &keyInfo2);

	IMSG("Open Persistent Key Info - objectType: %x, objectUsage:  %x, objectSize: %d, maxObjectSize: %d, handleFlags:%x  datasize: %d, dataposition: %d\n", keyInfo2.objectType, keyInfo2.objectUsage, keyInfo2.objectSize, keyInfo2.maxObjectSize, keyInfo2.handleFlags, keyInfo2.dataSize, keyInfo2.dataPosition);

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */
	/*  Allocate memory for the IV, destination data, void source data, and deciphered data*/
	IV = TEE_Malloc(IVlen, 0);

	if (!IV) 
	{
		IMSG("Out of memory for IV.");
		goto cleanup2;
	}

	TEE_GenerateRandom(IV, IVlen);

	IMSG("IV generated with success.\n");	

	destData = TEE_Malloc(destLen, 0);

	if (!destData) 
	{
		IMSG("Out of memory for destData.");
		goto cleanup3;
	}

	IMSG("destData allocated with success.\n");	
	
	void_srcData = TEE_Malloc(srcLen, 0);

	if (!void_srcData) 
	{
		IMSG("Out of memory for void_srcData.");
		goto cleanup4;
	}

	IMSG("void_srcData allocated with success.\n");	

	TEE_MemMove(void_srcData, srcData, srcLen);

	IMSG("srcData moved to void_srcData with success.\n");	

	decipheredData= TEE_Malloc(decipheredLen, 0);

	if (!decipheredData) 
	{
		IMSG("Out of memory for decipheredData.");
		goto cleanup5;
	}

	IMSG("decipheredData allocated with success.\n");

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */
	/* Call function to cipher the input data */
	result = cipher_operation(*(session_data->cipher_op), persistent_key, TEE_MODE_ENCRYPT, IV, IVlen, algorithm, void_srcData, srcLen, destData, &destLen);

	if (result != TEE_SUCCESS) {
		IMSG("Cipher operation failded: 0x%x", result);
		goto cleanup6;
	}

	IMSG("Cipher operation executed with success.\n");

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */
	/* Call function to decipher the input data */
	result = cipher_operation(*(session_data->cipher_op), persistent_key, TEE_MODE_DECRYPT, IV, IVlen, algorithm, destData, destLen, decipheredData, &decipheredLen);

	if (result != TEE_SUCCESS) {
		IMSG("Cipher operation failded: 0x%x", result);
		goto cleanup6;
	}

	IMSG("Cipher operation executed with success.\n");

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */
	/* Compare ciphered and deciphered text to see if it was well encrypted and decrypted */
	
	result = TEE_MemCompare(decipheredData, srcData, decipheredLen);
	
	if (result != TEE_SUCCESS) {
		IMSG("Plain text is NOT matching with the deciphered text.");
		goto cleanup6;
	}

	IMSG("Plain text MATCHES with the deciphered text.");

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */
	cleanup6:
		TEE_Free(decipheredData);
	cleanup5:
		TEE_Free(void_srcData);
	cleanup4:		
		TEE_Free(destData);
	cleanup3:
		TEE_Free(IV);
	cleanup2:
		TEE_CloseObject(persistent_key);
	cleanup1:		
		return result;
}


static TEE_Result digest_operation(Session_data * session_data)
{
	/* Return */
	TEE_Result result = TEE_SUCCESS;

	/* Digest operation */
	uint32_t algorithm = TEE_ALG_SHA512;
	uint32_t mode = TEE_MODE_DIGEST;
	uint32_t keySize = 0;

	/* Messages */
	char plainMessage[] = "Miraje is the boss!";
	size_t plain_len = 19;
	void * voidPlainMsg = NULL;
	char hash[128] = {0};
	size_t hashLen = 128;

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */
	/* Allocate a handle for a digest operation = DIGEST_INIT */
	result = TEE_AllocateOperation(session_data->digest_op, algorithm, mode, keySize);

	if (result != TEE_SUCCESS) {
		IMSG("Failed to allocate digest operation handle : 0x%x", result);
		goto cleanup1;
	}

	IMSG("Digest operation handle allocated with success.\n");

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */
	/* Allocate memory for voidPlainMsg */
	voidPlainMsg = TEE_Malloc(plain_len, 0);

	if(!voidPlainMsg)
	{
		IMSG("Out of memory for voidPlainMsg.");
		goto cleanup2;
	}

	IMSG("voidPlainMsg allocated with success.\n");	

	TEE_MemMove(voidPlainMsg, plainMessage, (uint32_t)plain_len);

	IMSG("Plain message copied to voidPlainMsg with success.\n");

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */
	/* Accumulates message data for hashing = DIGEST_UPDATE */
	TEE_DigestUpdate(*(session_data->digest_op), voidPlainMsg, plain_len);

	IMSG("DigestUpdate operation executed with success.\n");

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */
	/* Finalize the message digest operation and produce the message hash */
	result = TEE_DigestDoFinal(*(session_data->digest_op), NULL, 0, hash, &hashLen);

	if(result != TEE_SUCCESS)
	{
		IMSG("Failed to do digestDoFinal operation : 0x%x", result);
		goto cleanup3;
	}

	IMSG("DigestDoFinal operation executed with success.\n");

	dump_hash(hash, hashLen);

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */
	/* cleanup resources */
	cleanup3:
		TEE_Free(voidPlainMsg);
	cleanup2:
		TEE_FreeOperation(*(session_data->digest_op));
	cleanup1:
		return result;

}

/*============================================================================

	Encrypt initi function

============================================================================*/
static TEE_Result encrypt_init_func(Session_data * session_data, TEE_Param params[4], uint32_t param_types)
{
	/* Return */
	TEE_Result result = TEE_SUCCESS;

	/* Transient key */
	TEE_ObjectHandle transient_key =  TEE_HANDLE_NULL;
	TEE_ObjectInfo keyInfo;
	uint32_t keyType = TEE_TYPE_AES;
	uint32_t keySize = 128;

	/* Cipher operation */
	uint32_t algorithm = TEE_ALG_AES_CTS;
	uint32_t mode = TEE_MODE_ENCRYPT;
	void * IV = NULL;
	size_t IVlen = 20;

	/* Expected parameters */
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */
	/* Allocate an uninitialized transient object */
	keySize = params[0].value.a;

	result = TEE_AllocateTransientObject(keyType, keySize, &transient_key);

	if (result != TEE_SUCCESS) {
		IMSG("Failed to Allocate transient object handle : 0x%x", result);
		goto cleanup1;
	}

	IMSG("Transient object for AES key allocated with success.\n");

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */
	/* Generate a random key and populates a transient key object with the generated key material */
	result = TEE_GenerateKey(transient_key, keySize, (TEE_Attribute *)NULL,  0);

	if (result != TEE_SUCCESS) {
		IMSG("Failed to generate a transient key: 0x%x", result);
		goto cleanup2;
	}

	IMSG("AES-256 key generated with success.\n");

	TEE_GetObjectInfo(transient_key, &keyInfo);

	IMSG("Transient Key Info - objectType: %x, objectUsage:  %x, objectSize: %d, maxObjectSize: %d, handleFlags:%x, datasize: %d, dataposition: %d\n", keyInfo.objectType, keyInfo.objectUsage, keyInfo.objectSize, keyInfo.maxObjectSize, keyInfo.handleFlags, keyInfo.dataSize, keyInfo.dataPosition);

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */
	/* Allocate a handle for a new cryptographic operation */
	result = TEE_AllocateOperation(session_data->cipher_op, algorithm, mode, keyInfo.maxObjectSize);

	if (result != TEE_SUCCESS) {
		IMSG("Failed to allocate an operation: 0x%x", result);
		goto cleanup2;
	}

	IMSG("Cryptographic operation allocated with success.\n");

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */
	/* Program the key of the operation */
	result = TEE_SetOperationKey(*(session_data->cipher_op), transient_key);

	if (result != TEE_SUCCESS) {
		IMSG("Failed to set operation key: 0x%x", result);
		/*goto cleanup3;*/
		goto cleanup2;
	}

	IMSG("Key for cryptographic operation set with success.\n");

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */	
	/* Start the symmetric cipher operation */
	IV = params[1].memref.buffer;
	IVlen = params[1].memref.size;

	/*dump_hash((char *)IV, IVlen);*/

	TEE_CipherInit(*(session_data->cipher_op), IV, IVlen);

	IMSG("Cipher operation initiated with success.\n");

	/*goto cleanup2;*/

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */	
	/*cleanup3:
		TEE_FreeOperation(*(session_data->digest_op));*/		
	cleanup2:
		TEE_FreeTransientObject(transient_key);
	cleanup1:
		return result;
}

/*============================================================================

	Encrypt update function

============================================================================*/
static TEE_Result encrypt_update_func(Session_data * session_data, TEE_Param params[4], uint32_t param_types)
{
	/* Return */
	TEE_Result result = TEE_SUCCESS;

	/* Cipher operation */
	void * srcData;
	void * destData;
	size_t srcLen;
	size_t destLen;
	size_t writen_bytes;
	size_t remaining_bytes;

	/* Expected parameters */
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */
	/* Encrypt the input data */
	srcData = params[0].memref.buffer;
	srcLen = params[0].memref.size;

	destData = params[1].memref.buffer;
	destLen = params[1].memref.size;
	
	writen_bytes = destLen;

	result = TEE_CipherUpdate(*(session_data->cipher_op), srcData, srcLen, destData, &writen_bytes);

	if (result != TEE_SUCCESS) {
		IMSG("Cipher operation Update failed : 0x%x", result);
		goto cleanup1;
	}	

	IMSG("Cipher operation updated with success (bytes written: %zu).\n", writen_bytes);

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */
	/* Finalize the cipher operation */
	remaining_bytes = destLen - writen_bytes;

	result = TEE_CipherDoFinal(*(session_data->cipher_op), (void *)NULL, 0, (unsigned char *)destData + writen_bytes, &remaining_bytes);

	if (result != TEE_SUCCESS) {
		IMSG("Cipher operation Do final failed : 0x%x", result);
		goto cleanup1;
	}

	IMSG("Cipher operation finalized with success (remaining bytes: %zu).\n", remaining_bytes);

	destLen = writen_bytes + remaining_bytes;

	IMSG("Cipher operation: destination total number of bytes: %zu.\n", destLen);

	params[1].memref.size = destLen;

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */
	cleanup1:
		return result;
}

/*============================================================================

	Encrypt final function

============================================================================*/
static TEE_Result encrypt_final_func(Session_data * session_data, TEE_Param params[4], uint32_t param_types)
{
	/* Return */
	TEE_Result result = TEE_SUCCESS;

	/* Expected parameters */
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	(void)&params;

	TEE_FreeOperation(*(session_data->cipher_op));	

	IMSG("Cipher operation released with success.\n");

	return result;
}	

/*============================================================================

	Digest init function

============================================================================*/
static TEE_Result digest_init_func(Session_data * session_data, TEE_Param params[4], uint32_t param_types)
{
	/* Return */
	TEE_Result result = TEE_SUCCESS;

	/* Digest operation */
	uint32_t algorithm = TEE_ALG_SHA1;
	uint32_t mode = TEE_MODE_DIGEST;
	uint32_t keySize = 0;

	/* Expected parameters */
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	(void)&params;

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */
	/* Allocate a handle for a digest operation = DIGEST_INIT */
	result = TEE_AllocateOperation(session_data->digest_op, algorithm, mode, keySize);

	if (result != TEE_SUCCESS) {
		IMSG("Failed to allocate digest operation handle : 0x%x", result);
		goto cleanup1;
	}

	IMSG("Digest operation handle allocated with success.\n");

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */
	cleanup1:
		return result;
}

/*============================================================================

	Digest update function

============================================================================*/
static TEE_Result digest_update_func(Session_data * session_data, TEE_Param params[4], uint32_t param_types)
{
	/* Return */
	TEE_Result result = TEE_SUCCESS;

	/* Digest operation */
	void * cipherText;
	size_t cipherTextSize;

	/* Expected parameters */
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */
	/* Accumulates message data for hashing = DIGEST_UPDATE */

	cipherText = params[0].memref.buffer;
	cipherTextSize = params[0].memref.size;

	TEE_DigestUpdate(*(session_data->digest_op), cipherText, cipherTextSize);

	IMSG("DigestUpdate operation executed with success.\n");

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */
	return result;

}

/*============================================================================

	Digest final function

============================================================================*/
static TEE_Result digest_final_func(Session_data * session_data, TEE_Param params[4], uint32_t param_types)
{
	/* Return */
	TEE_Result result = TEE_SUCCESS;

	/* Digest operation */
	void * hash;
	size_t * hashLen;

	/* Expected parameters */
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */
	/* Finalize the message digest operation and produce the message hash */
	hash = params[0].memref.buffer;
	hashLen = &params[0].memref.size;

	result = TEE_DigestDoFinal(*(session_data->digest_op), NULL, 0, hash, hashLen);

	if(result != TEE_SUCCESS)
	{
		IMSG("Failed to do digestDoFinal operation : 0x%x", result);
		goto cleanup1;
	}

	IMSG("DigestDoFinal operation executed with success.\n");

	dump_hash(hash, *hashLen);


	cleanup1:
		return result;
}

/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id, uint32_t param_types, TEE_Param params[4])
{

	switch (cmd_id) {
		case CMD_ENCRYPT: 
			return encrypt_operation((Session_data *)sess_ctx);
		case CMD_DIGEST: 
			return digest_operation((Session_data *)sess_ctx);
		case CMD_ENCRYPT_INIT:
			return encrypt_init_func((Session_data *)sess_ctx, params, param_types);
		case CMD_ENCRYPT_UPDATE:
			return encrypt_update_func((Session_data *)sess_ctx, params, param_types);
		case CMD_ENCRYPT_FINAL:
			return encrypt_final_func((Session_data *)sess_ctx, params, param_types);
		case CMD_DIGEST_INIT:
			return digest_init_func((Session_data *)sess_ctx, params, param_types);
		case CMD_DIGEST_UPDATE:
			return digest_update_func((Session_data *)sess_ctx, params, param_types);
		case CMD_DIGEST_FINAL:
			return digest_final_func((Session_data *)sess_ctx, params, param_types);
		default:
			return TEE_ERROR_BAD_PARAMETERS;
	}
}	
