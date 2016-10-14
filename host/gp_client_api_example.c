#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <tee_client_api.h>
#include <ta_gp_client_api_example.h>

static void dump_hash(char *hash, size_t len)
{
	size_t i;

	printf("\t--------------------------------------------------------------------------------------------------------------------------------------\n\t");

	for (i = 0; i < len; i++)
		printf("hash: %02x", hash[i]);

	printf("\n\t--------------------------------------------------------------------------------------------------------------------------------------\n");
}


TEEC_Result crypto_session(char * inputBuffer, size_t inputBufferSize, char * outputBuffer, size_t outputBufferSize, uint8_t * digestBuffer)
{
	/* Result */
	TEEC_Result	result = TEEC_SUCCESS;

	/* Session and context */
	TEEC_Context context;
	TEEC_Session session;

	TEEC_UUID uuid = TA_GP_CLIENT_API_EXAMPLE_UUID;	
	uint32_t err_origin;

	/* Cipher operation */
	TEEC_Operation operation;

	/* Shared memories */
	TEEC_SharedMemory commsSM;
	TEEC_SharedMemory inputSM;
	TEEC_SharedMemory outputSM;

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */
	result = TEEC_InitializeContext(NULL, &context);

	if (result != TEEC_SUCCESS)
	{
		errx(1, "TEEC_InitializeContext failed with error code 0x%x ", result);
		goto cleanup1;
	}	

	printf("\t-Context intialized with success.\n");	
	
	result = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);

	if (result != TEEC_SUCCESS)
	{
		errx(1, "TEEC_OpenSession failed with code 0x%x origin 0x%x", result, err_origin);
		goto cleanup2;
	}
		
	printf("\t-Session opened with success.\n");

	
	result = TEEC_InvokeCommand(&session, CMD_ENCRYPT, NULL, NULL);

	if (result != TEEC_SUCCESS)
	{
		errx(1, "TEEC_InvokeCommand with CMD_CREATE_KEY failed and returned error code 0x%x", result);
		goto cleanup3;
	}

	printf("\t-CMD_ENCRYPT executed with success.\n");	

	result = TEEC_InvokeCommand(&session, CMD_DIGEST, NULL, NULL);

	if (result != TEEC_SUCCESS)
	{
		errx(1, "TEEC_InvokeCommand with CMD_DIGEST_INIT failed and returned error code 0x%x", result);
		goto cleanup3;
	}		

	printf("\t-CMD_DIGEST executed with success.\n");
	

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */	
	/* Shared memory setup */
		commsSM.size = 20; /* Size of hash */
		commsSM.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

		result = TEEC_AllocateSharedMemory(&context, &commsSM);

		if (result != TEEC_SUCCESS)
		{
			errx(1, "TEEC_AllocateSharedMemory for commsSM failed with code 0x%x origin 0x%x",	result, err_origin);
			goto cleanup3;
		}
		
		printf("\t-commsSM shared memory allocated with success.\n");

	/* ................................ */
	
		inputSM.buffer = inputBuffer;
		inputSM.size = inputBufferSize;
		inputSM.flags = TEEC_MEM_INPUT;

		result = TEEC_RegisterSharedMemory(&context, &inputSM);

		if (result != TEEC_SUCCESS)
		{
			errx(1, "TEEC_RegisterSharedMemory for inputSM failed with code 0x%x origin 0x%x",	result, err_origin);
			goto cleanup4;
		}
		
		printf("\t-inputSM shared memory registred with success.\n");

	/* ................................ */
	
		outputSM.buffer = outputBuffer;
		outputSM.size = outputBufferSize;
		outputSM.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

		result = TEEC_RegisterSharedMemory(&context, &outputSM);

		if (result != TEEC_SUCCESS)
		{
			errx(1, "TEEC_RegisterSharedMemory for inputSM failed with code 0x%x origin 0x%x",	result, err_origin);
			goto cleanup5;
		}
		
		printf("\t-inputSM shared memory registred with success.\n");

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */	
	/* Cipher Initialization */
	memset(&operation, 0, sizeof(operation));

	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE, TEEC_NONE);

	operation.params[0].value.a = 256; /* AES key size */

	operation.params[1].memref.parent = &commsSM;
	operation.params[1].memref.size = 16;
	operation.params[1].memref.offset = 0;

	memset(commsSM.buffer, 2, 16); /* setting the IV */

	result = TEEC_InvokeCommand(&session, CMD_ENCRYPT_INIT, &operation, &err_origin);

	if(result != TEEC_SUCCESS)
	{
		errx(1, "TEEC_InvokeCommand for CMD_ENCRYPT_INIT failed with code 0x%x origin 0x%x", result, err_origin);
		goto cleanup6;
	}

	printf("\t-CMD_ENCRYPT_INIT operation executed with success.\n");

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */	
	/* Digest Initialization */

	result = TEEC_InvokeCommand(&session, CMD_DIGEST_INIT, NULL, &err_origin);

	if(result != TEEC_SUCCESS)
	{
		errx(1, "TEEC_InvokeCommand for CMD_DIGEST_INIT failed with code 0x%x origin 0x%x", result, err_origin);
		goto cleanup6;
	}

	printf("\t-CMD_DIGEST_INIT operation executed with success.\n");

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */	
	/* Cipher encryption */
	memset(&operation, 0, sizeof(operation));

	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_NONE, TEEC_NONE);	

	operation.params[0].memref.parent = &inputSM;

	operation.params[1].memref.parent = &outputSM;
	operation.params[1].memref.size = outputBufferSize;
	operation.params[1].memref.offset = 0;	

	result = TEEC_InvokeCommand(&session, CMD_ENCRYPT_UPDATE, &operation, &err_origin);

	if(result != TEEC_SUCCESS)
	{
		errx(1, "TEEC_InvokeCommand for CMD_ENCRYPT_UPDATE failed with code 0x%x origin 0x%x", result, err_origin);
		goto cleanup6;
	}

	printf("\t-CMD_ENCRYPT_UPDATE operation executed with success.\n");

 	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */	
	/* Digest update */
	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);	

	operation.params[0].memref.parent = &outputSM;
	operation.params[0].memref.size = operation.params[1].memref.size;
	operation.params[0].memref.offset = 0;	

	result = TEEC_InvokeCommand(&session, CMD_DIGEST_UPDATE, &operation, &err_origin);

	if(result != TEEC_SUCCESS)
	{
		errx(1, "TEEC_InvokeCommand for CMD_DIGEST_UPDATE failed with code 0x%x origin 0x%x", result, err_origin);
		goto cleanup6;
	}

	printf("\t-CMD_DIGEST_UPDATE operation executed with success.\n");


	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */	
	/* Cipher cleanup */

	result = TEEC_InvokeCommand(&session, CMD_ENCRYPT_FINAL, NULL, &err_origin);

	if(result != TEEC_SUCCESS)
	{
		errx(1, "TEEC_InvokeCommand for CMD_ENCRYPT_FINAL failed with code 0x%x origin 0x%x", result, err_origin);
		goto cleanup6;
	}

	printf("\t-CMD_ENCRYPT_FINAL operation executed with success.\n");

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */	
	/* Digest final */
	memset(&operation, 0, sizeof(operation));

	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);	

	operation.params[0].memref.parent = &commsSM;
	operation.params[0].memref.size = 20;
	operation.params[0].memref.offset = 0;	

	result = TEEC_InvokeCommand(&session, CMD_DIGEST_FINAL, &operation, &err_origin);

	if(result != TEEC_SUCCESS)
	{
		errx(1, "TEEC_InvokeCommand for CMD_DIGEST_FINAL failed with code 0x%x origin 0x%x", result, err_origin);
		goto cleanup6;
	}

	printf("\t-CMD_DIGEST_FINAL operation executed with success.\n");

 	dump_hash(commsSM.buffer, 20);

 	memcpy(digestBuffer, commsSM.buffer, 20);

	/*------------------------------------------------------------------------------------------------------------------------------------------------------- */	
	/* Cleanup resources */
	cleanup6:
		TEEC_ReleaseSharedMemory(&outputSM);
	cleanup5:
		TEEC_ReleaseSharedMemory(&inputSM);
	cleanup4:
		TEEC_ReleaseSharedMemory(&commsSM);
	cleanup3:
		TEEC_CloseSession(&session);
	cleanup2:
		TEEC_FinalizeContext(&context);
	cleanup1:
		return result;
}

/*========================================================================
		MAIN FUNCTION
========================================================================*/

int main(int argc, char *argv[])
{	
	int i = 0;
	char inputBuffer[] = "Miraje is the boss!";
	size_t inputBufferSize = 32;
	char * outputBuffer;
	size_t outputBufferSize = inputBufferSize;
	uint8_t * digestBuffer;
	size_t digestBufferSize = 20;

	outputBuffer = (char *)malloc(outputBufferSize * sizeof(char));
	digestBuffer = (uint8_t *)malloc(digestBufferSize * sizeof(uint8_t));

	printf("\n");

	i = crypto_session(inputBuffer, inputBufferSize, outputBuffer, outputBufferSize, digestBuffer);

	printf("\t-crypto_session result: %d\n", i);

	if(i != 0)
	{
		printf("\t-Unsuccessfuly finished crypto session\n");
		return -1;
	}

	printf("\t-Successfuly finished crypto session\n");

	printf("\n");

	return 0;
}
