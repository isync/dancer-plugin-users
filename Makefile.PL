
use ExtUtils::MakeMaker;

WriteMakefile(
	NAME		=> 'Dancer::Plugin::Users',
	VERSION_FROM	=> 'lib/Dancer/Plugin/Users.pm',
	ABSTRACT_FROM	=> 'lib/Dancer/Plugin/Users.pm',
	AUTHOR		=> 'isync',
	PREREQ_PM	=> {
		'Dancer' 			=> 0,
		'Dancer::Plugin::Database'	=> 0,
		'Dancer::Plugin::Passphrase'	=> 0,
		'Net::OpenID::Consumer'		=> 0,
		'Digest::SHA1'			=> 0,
		'LWPx::ParanoidAgent'		=> 0,
		'Data::Dumper'			=> 0,
	},
	META_MERGE	=> {	# CPAN::Meta::Spec
		resources	=> {
			repository => 'https://github.com/isync/dancer-plugin-users',
		},
	}
);
