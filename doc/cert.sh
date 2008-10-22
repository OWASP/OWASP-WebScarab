#!/bin/sh

if [ ! -d sslcerts ] ; then
  mkdir sslcerts || die "Couldn't create sslcerts directory"
fi
if [ ! -d sslcerts/certs ] ; then
  mkdir sslcerts/certs || die "Couldn't create certs directory"
fi
if [ ! -d sslcerts/private ] ; then
  mkdir sslcerts/private || die "Couldn't create private directory"
fi
if [ ! -f sslcerts/serial ] ; then
  echo '100001' > sslcerts/serial
fi
touch sslcerts/certindex.txt
if [ ! -f sslcerts/openssl.cnf ] ; then
  cat <<-EOF > sslcerts/openssl.cnf
	#
	# OpenSSL configuration file.
	#

	# Establish working directory.
 
	dir			= .

	[ ca ]
	default_ca		= CA_default

	[ CA_default ]
	serial			= ./serial
	database		= ./certindex.txt
	new_certs_dir		= ./certs
	certificate		= ./ca_cert.pem
	private_key		= ./private/ca_key.pem
	default_days		= 365
	default_md		= md5
	preserve		= no
	email_in_dn		= no
	nameopt			= default_ca
	certopt			= default_ca
	policy			= policy_anything

	[ policy_match ]
	countryName		= match
	stateOrProvinceName	= match
	organizationName	= match
	organizationalUnitName	= match
	commonName		= supplied
	emailAddress		= optional

	[ policy_anything ]
	countryName		= optional
	stateOrProvinceName	= optional
	localityName		= optional
	organizationName	= optional
	organizationalUnitName	= optional
	commonName		= supplied
	emailAddress		= optional

 
	[ req ]
	default_bits		= 1024			# Size of keys
	default_keyfile		= key.pem		# name of generated keys
	default_md		= md5			# message digest algorithm
	string_mask		= nombstr		# permitted characters
	distinguished_name	= req_distinguished_name
	req_extensions		= v3_req
 
	[ req_distinguished_name ]
	# Variable name				Prompt string
	#-------------------------	  ----------------------------------
	0.organizationName	= Organization Name (company)
	organizationalUnitName	= Organizational Unit Name (department, division)
	emailAddress		= Email Address
	emailAddress_max	= 40
	localityName		= Locality Name (city, district)
	stateOrProvinceName	= State or Province Name (full name)
	countryName		= Country Name (2 letter code)
	countryName_min		= 2
	countryName_max		= 2
	commonName		= Common Name (hostname, IP, or your name)
	commonName_max		= 64

	# Default values for the above, for consistency and less typing.
	# Variable name			Value
	#------------------------  ------------------------------
	0.organizationName_default	= WebScarab
	localityName_default		= WebScarab
	stateOrProvinceName_default	= WebScarab
	countryName_default		= ZA
 
	[ v3_ca ]
	basicConstraints		= CA:TRUE
	subjectKeyIdentifier		= hash
	authorityKeyIdentifier		= keyid:always,issuer:always

	[ v3_req ]
	basicConstraints		= CA:FALSE
	subjectKeyIdentifier		= hash
	EOF
fi

if [ ! -f sslcerts/private/ca_key.pem -a ! -f sslcerts/ca_cert.p12 ] ; then
  printf "\n\n\n\n\n\n\n" | \
  openssl req -new -x509 -extensions v3_ca -keyout sslcerts/private/ca_key.pem \
    -out sslcerts/ca_cert.pem -days 3650 -config ./sslcerts/openssl.cnf \
    -passin pass:password -passout pass:password
fi

cd sslcerts

# Create the cert for the specified site
if [ ! -f $1-req.pem ] ; then
  printf "\n\n\n\n\n\n$1\n" | \
  openssl req -new -nodes \
    -out $1-req.pem -keyout ./private/$1-key.pem \
    -days 3650 -config ./openssl.cnf
fi

if [ ! -f $1-cert.pem ] ; then
  printf "y\ny\n" | \
  openssl ca -out $1-cert.pem -days 3650 \
    -key password -config ./openssl.cnf -infiles $1-req.pem
fi

if [ ! -f ../$1.p12 ] ; then
  openssl pkcs12 -export -in $1-cert.pem -inkey ./private/$1-key.pem \
    -certfile ca_cert.pem -out ../$1.p12 -password pass:password
fi

