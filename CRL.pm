## OpenCA::CRL
##
## Copyright (C) 1998-1999 Massimiliano Pala (madwolf@openca.org)
## All rights reserved.
##
## This library is free for commercial and non-commercial use as long as
## the following conditions are aheared to.  The following conditions
## apply to all code found in this distribution, be it the RC4, RSA,
## lhash, DES, etc., code; not just the SSL code.  The documentation
## included with this distribution is covered by the same copyright terms
## 
## Copyright remains Massimiliano Pala's, and as such any Copyright notices
## in the code are not to be removed.
## If this package is used in a product, Massimiliano Pala should be given
## attribution as the author of the parts of the library used.
## This can be in the form of a textual message at program startup or
## in documentation (online or textual) provided with the package.
## 
## Redistribution and use in source and binary forms, with or without
## modification, are permitted provided that the following conditions
## are met:
## 1. Redistributions of source code must retain the copyright
##    notice, this list of conditions and the following disclaimer.
## 2. Redistributions in binary form must reproduce the above copyright
##    notice, this list of conditions and the following disclaimer in the
##    documentation and/or other materials provided with the distribution.
## 3. All advertising materials mentioning features or use of this software
##    must display the following acknowledgement:
##    "This product includes OpenCA software written by Massimiliano Pala
##     (madwolf@openca.org) and the OpenCA Group (www.openca.org)"
## 4. If you include any Windows specific code (or a derivative thereof) from 
##    some directory (application code) you must include an acknowledgement:
##    "This product includes OpenCA software (www.openca.org)"
## 
## THIS SOFTWARE IS PROVIDED BY OPENCA DEVELOPERS ``AS IS'' AND
## ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
## IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
## ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
## FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
## DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
## OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
## HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
## LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
## OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
## SUCH DAMAGE.
## 
## The licence and distribution terms for any publically available version or
## derivative of this code cannot be changed.  i.e. this code cannot simply be
## copied and put under another distribution licence
## [including the GNU Public Licence.]
##
use strict;

package OpenCA::CRL;

$OpenCA::CRL::VERSION = '0.7.5a';

my %params = {
	clr => undef, 
	item => undef,
	pwd => undef, 
	crlFormat => undef,
	pemCRL => undef,
	derCRL => undef,
	txtCRL => undef,
	parsedItem => undef,
	backend => undef,
	beginHeader => undef,
	endHeader => undef
};

sub new {
	my $that = shift;
	my $class = ref($that) || $that;

        my $self = {
		%params,
	};

        bless $self, $class;

        my $keys = { @_ };

        $self->{crl}       = $keys->{DATA};
        $self->{pwd}       = $keys->{PASSWD};
        $self->{crlFormat} = ( $keys->{FORMAT} or $keys->{INFORM} or "PEM");
        $self->{backend}   = $keys->{SHELL};

	return if( not $self->{backend} );

	my $infile = $keys->{INFILE};
	my $cakey  = $keys->{CAKEY};
	my $cacert = $keys->{CACERT};
	my $days   = $keys->{DAYS};
	my $exts   = $keys->{EXTS};

	$self->{beginHeader} = "-----BEGIN HEADER-----";
	$self->{endHeader} = "-----END HEADER-----";

        if ( $infile ne "" ) {
		my $tmpLine;
		open( FD, "<$infile" ) or return;
			while( $tmpLine = <FD> ) {
				$self->{crl} .= $tmpLine;
			}
		close(FD);
        }

	if( ($cacert) or ($cakey) ) {
		return unless ( $cacert and $cakey );

		$self->{crl} = $self->{backend}->issueCrl( CAKEY=>$cakey,
					   CACERT=>$cacert,
					   OUTFORM=>$self->{crlFormat},
					   DAYS=>$days,
					   PASSWD=>$self->{pwd},
					   EXTS=>$exts );

		return if ( not $self->{crl} );
	}


        if ( $self->{crl} ne "" ) {
		$self->{item} = $self->{crl};

		$self->{crl} = $self->getBody( ITEM=>$self->{item} );

                if ( not $self->initCRL( CRL=>$self->{crl},
                                         FORMAT=>$self->{crlFormat} )) {
                        return;
                }

        }

	return $self;
}


sub initCRL {
        my $self = shift;
        my $keys = { @_ };

        return if (not $self->{crl});

        $self->{pemCRL} = $self->{backend}->dataConvert( DATA=>$self->{crl},
                                        DATATYPE=>"CRL",
                                        INFORM=>$self->{crlFormat},
                                        OUTFORM=>"PEM" );
        $self->{derCRL} = $self->{backend}->dataConvert( DATA=>$self->{crl},
                                        DATATYPE=>"CRL",
                                        INFORM=>$self->{crlFormat},
                                        OUTFORM=>"DER" );
        $self->{txtCRL} = $self->{backend}->dataConvert( DATA=>$self->{crl},
                                        DATATYPE=>"CRL",
                                        INFORM=>$self->{crlFormat},
                                        OUTFORM=>"TXT" );

        $self->{parsedItem} = $self->parseCRL( CRL=>$self->{txtCRL} );

        return if ( (not $self->{pemCRL}) or (not $self->{derCRL})
                 or (not $self->{txtCRL}) or (not $self->{parsedItem}) );

        return 1;
}

sub parseCRL {

	my $self = shift;
	my $keys = { @_ };

	my ( $version, $issuer, $last, $next, $alg, $tmp);
	my @list;
	my @certs;

	my $textCRL = $keys->{CRL};
	my ( $head, $body );

	my $startLine = 'Certificate Revocation List \(CRL\)\:';
	my $listStartLine = 'Revoked Certificates[\:\.]';
	my $listEndLine = 'Signature Algorithm\:';

	( $head ) = ( $textCRL =~ /$startLine([\s\S\n]+)$listStartLine/ );
	( $body ) = ( $textCRL =~ /$listStartLine([\s\S\n]+)$listEndLine/ );

	return if ( not $head );

	( $version ) = ( $head =~ /Version ([a-e\d]+)/i );
	( $alg )     = ( $head =~ /Signature Algorithm: (.*?)\n/i );
	( $issuer )  = ( $head =~ /Issuer: (.*?)\n/i );
	( $last )    = ( $head =~ /Last Update: (.*?)\n/i );
	( $next )    = ( $head =~ /Next Update: (.*?)\n/i );

	## Parse lines ...
	@certs = split ( /Serial Number: /i, $body );
	foreach $tmp (@certs) {
		my ( $line1, $line2 ) = split ( /\n/, $tmp );
		next if ( (not $line1) or (not $line2) );

		my ( $serial ) =
			( $line1 =~ /[\s]*([a-f\d]+)/i );
		my ( $date ) =
			( $line2 =~ /Revocation Date: (.*)/i );

		if ( length( $serial ) % 2 ) {
			$serial = "0" . $serial;
		}

		my $entry = {
			SERIAL=>$serial,
			DATE=>$date }; 

		@list = ( @list, $entry );
	}

	my $ret = {
			VERSION=>$version,
			ALGORITHM=>$alg,
		  	ISSUER=>$issuer,
		  	LAST_UPDATE=>$last,
		  	NEXT_UPDATE=>$next,
			BODY => $self->getBody( ITEM=> $self->{item} ),
			ITEM => $self->getBody( ITEM=> $self->{item} ),
			HEADER => $self->getHeader ( ITEM=>$self->{item} ),
		  	LIST=>[ @list ]
		  };

	return $ret;
}

sub getHeader {
	my $self = shift;
	my $keys = { @_ };
	my $req = $keys->{ITEM};

	my ( $txt, $ret, $i, $key, $val );

	my $beginHeader = $self->{beginHeader};
	my $endHeader = $self->{endHeader};

	if( ($txt) = ( $req =~ /$beginHeader\n([\S\s\n]+)\n$endHeader/m) ) {
		foreach $i ( split ( /\n/, $txt ) ) {
			$i =~ s/\s*=\s*/=/;
			( $key, $val ) = ( $i =~ /(.*)\s*=\s*(.*)\s*/ );
			$ret->{$key} = $val;
		}
	}

	return $ret;
}

sub getBody {
	my $self = shift;
	my $keys = { @_ };

	my $ret = $keys->{ITEM};

	my $beginHeader 	= $self->{beginHeader};
	my $endHeader 		= $self->{endHeader};

	## Let's throw away text between the two headers, included
	$ret =~ s/($beginHeader[\S\s\n]+$endHeader\n)//;

	return $ret;
}

sub getTXT {
	my $self = shift;

	return if( not $self->{txtCRL} );
	return $self->{txtCRL};
}

sub getParsed {
	my $self = shift;

	return if ( not $self->{parsedItem} );
	return $self->{parsedItem};
}

sub getPEM {
	my $self = shift;

	return if( not $self->{pemCRL} );
	return $self->{pemCRL};
}

sub getDER {
	my $self = shift;

	return if( not $self->{derCRL} );
	return $self->{derCRL};
}

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

OpenCA::CRL - CRL Management module.

=head1 SYNOPSIS

use OpenCA::CRL;

=head1 DESCRIPTION

This module contains functions to access CRLs infos. It, as the
OpenCA::X509 module, requires some parameters such as a reference
to an OpenCA::OpenSSL instance. This module provides a CRL->PERL
Hashes parsing, no specific crypto functions are performed.

=head1 FUNCTIONS

=head2 sub new () - Create a new instance of the Class.

	Creating a new instance of the module you can provide a
	valid crl. As a result the crl will be parsed and stored
	in local variable(s) for later usage. You can generate a
	new instance of the class either by giving an already
	issued CRL (see OpenCA::OpenSSL for documentation) or
	even generate a new CRL if you provide the CACERT and
	CAKEY. The function will return a self reference. Accepted
	parameters are:

		SHELL   - An OpenCA::OpenSSL initialized
			  instance;
		CRL	- A valid CRL(*);
		INFILE	- A CRL file(*);
		FORMAT  - Format of the provided CRL. Supported
			  are PEM|DER(*);
		CAKEY	- CA private key file(*);
		CACERT	- CA certificate file(*);
		DAYS	- Days the CRL will be valid(*);
		EXTS	- Extentions section (see openssl.cnf
			  documentation)(*);

	(*) - Optional Parameters;

	EXAMPLE:

	   my $self->{crl} = new OpenCA::CRL( SHELL=>$openssl, CRL=>$pemCRL );

	NOTE: When you generate a new CRL, you have to provide
	      BOTH CAKEY and CACERT parameters.

=head2 sub initCRL () - Initialize internal CRL parameters.

	Initialize the module with a provided CRL. You can not
	generate a new CRL with this function, if you wish to
	do so you'll have to get a new instance of the class
	(see the new() function). Accepted parameters are:

		CRL     - Provided CRL(*);
		INFILE  - A CRL file (one of CRL/INFILE params
			  is required)(*);
		FORMAT	- Provided CRL format (PEM|DER)(*);

	(*) - Optional Parameters;

	EXAMPLE:

		if( not $self->{crl}->initCRL(CRL=>$derCRL, FORMAT=>DER)) {
                     print "Error!";
                }

=head2 sub getParsed () - Retrieve parsed CRL list

	This function returns an HASH structure with the main CRL
	data and a list of HASH with SERIAL and DATE of revoked
	certificates. Returned value is:

		my $ret = { VERSION=>$version,
                  	    ALGORITHM=>$alg,
                  	    ISSUER=>$issuer,
                  	    LAST_UPDATE=>$last,
                  	    NEXT_UPDATE=>$next,
                  	    LIST=>[ @list ] };

	Each element of the LIST has the following format:
	
		my $element = { SERIAL=>$certSerial,
				DATE=>$revDate };


	EXAMPLE:

		print "VERSION: " . $self->{crl}->getParsed()->{VERSION};

                foreach $rev ( @{ $self->{crl}->getParsed()->{LIST} } ) {
                    print "SERIAL: " . $rev->{SERIAL} . "\n";
                    print "DATE: " . $rev->{DATE} . "\n";
                }

=head2 sub getPEM () - Get the CRL in a PEM format.

	This function accept no arguments and returns the CRL in
	PEM format.

	EXAMPLE:

		$pem = $crl->getPEM();

=head2 sub getDER () - Get the CRL in a DER format.

	This function accept no arguments and returns the CRL in
	DER format.

	EXAMPLE:

		$der = $crl->getDER();

=head2 sub getTXT () - Get the CRL in a TXT format.

	This function accept no arguments and returns the CRL in
	TXT format.

	EXAMPLE:

		print $crl->getTXT();

=head1 AUTHOR

Massimiliano Pala <madwolf@openca.org>

=head1 SEE ALSO

OpenCA::X509, OpenCA::Tools, OpenCA::OpenSSL, OpenCA::REQ,
OpenCA::TRIStateCGI, OpenCA::Configuration

=cut
