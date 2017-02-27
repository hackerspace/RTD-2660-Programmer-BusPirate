#include <stdint.h>
#include <assert.h>
#include <stdio.h>

#include <linux/i2c-dev.h>
#include <sys/ioctl.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#include <string.h>

static int iDevice = -1;
const char* sDevice = "/dev/i2c-1";

bool InitI2C ()
{
	assert (iDevice==-1);
	if ( (iDevice = open ( sDevice, O_RDWR ))<0 )
	{
		/* ERROR HANDLING: you can check errno to see what went wrong */
		perror ( "Failed to open the i2c bus" );
		exit ( 1 );
	}
	return true;
}

void CloseI2C ()
{
	if ( iDevice>=0 )
		::close(iDevice);
	iDevice = -1;
}


void SetI2CAddr(uint8_t value)
{
	assert(iDevice!=0);

	if ( ioctl ( iDevice, I2C_SLAVE, value )<0 )
	{
		perror ( "Failed to acquire bus access and/or talk to slave.\n" );
		/* ERROR HANDLING; you can check errno to see what went wrong */
		exit ( 1 );
	}
}

bool WriteBytesToAddr ( uint8_t reg, uint8_t * values, uint8_t len )
{
	assert ( iDevice>0 );
	uint8_t buf[64];
	if ( len>63 )
	{
		len = 63;
	}
	size_t buflen = len + 1;
	buf[0] = reg;
	for ( int idx = 0; idx<len; idx++ )
	{
		buf[1 + idx] = values[idx];
	}
	ssize_t iWritten = ::write ( iDevice, buf, buflen );

	return iWritten==buflen;
}

static void ReadBytes ( uint8_t * dest, uint8_t len=64 )
{
	::read ( iDevice, dest, len );
}

bool ReadBytesFromAddr ( uint8_t reg, uint8_t * dest, uint8_t len )
{
	uint8_t buf[2];
	size_t buflen = sizeof ( buf );
	buf[0] = reg;
	buf[1] = len;
	::write ( iDevice, buf, buflen );

	ReadBytes ( dest, len );
}

uint8_t ReadByteFromAddr ( uint8_t reg )
{
	uint8_t result;
	::write ( iDevice, &reg, 1 );
	ReadBytes ( &result, 1 );
	return result;
}

uint8_t ReadReg ( uint8_t reg )
{
	return ReadByteFromAddr ( reg );
}

bool WriteReg ( uint8_t reg, uint8_t value )
{
	return WriteBytesToAddr ( reg, &value, 1 );
}