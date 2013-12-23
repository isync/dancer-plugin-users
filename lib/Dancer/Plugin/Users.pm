package Dancer::Plugin::Users;

use Dancer ':syntax';
use Dancer::Plugin;
use Dancer::Plugin::Database;
use Dancer::Plugin::Passphrase;
use Net::OpenID::Consumer;
use Digest::SHA1;
use LWPx::ParanoidAgent;
use Data::Dumper;

our $VERSION = '0.02';

our $conf = config->{plugins}->{Users}; # plugin_setting();
$conf->{route_login}		||= '/login';
$conf->{route_openid_login}	||= '/openid_login';
$conf->{route_logout}		||= '/logout';
$conf->{route_register} 	||= '/register';
$conf->{route_openid_register}	||= '/openid_register';
$conf->{route_end_membership}	||= '/end_membership';
$conf->{reserved_logins}	||= 'admin root superuser demo Anonymous test';
$conf->{db_table}		||= 'users';

## build and precompile reserved_logins regex
if($conf->{reserved_logins}){
	$conf->{reserved_logins_regex} = '^' . join('$|^', split(/\s+/,$conf->{reserved_logins}) ) . '$';
	$conf->{reserved_logins_regex} = qr/$conf->{reserved_logins_regex}/i;
}

## Check if we can get a database connection
our $dbh = database($conf->{db_connection_name});
die "No database handle" if !$dbh;

## Check if the db has the users table
my $check = database()->do("SELECT * FROM $conf->{db_table} LIMIT 1; "); # more portable than "SHOW TABLES LIKE 'x'"; also, we don't check for  or die database()->errstr
unless($check){
	Dancer::Logger::info("Creating database table '$conf->{db_table}'");

	## create a user db with cache-fields for the 9 optional values supplied via OpenID
	## http://openid.net/specs/openid-simple-registration-extension-1_0.html#response_format
	my $sql = "create table `users` (
		`id` integer primary key AUTOINCREMENT,
		`nickname` varchar(32) null,
		`openid_identity` varchar(128) null,
		`password` varchar(68) null,
		`email` varchar(128) null,
		`fullname` varchar(128) null,
		`dob` varchar(32) null,
		`gender` varchar(16) null,
		`postcode` varchar(16) null,
		`country` varchar(32) null,
		`language` varchar(16) null,
		`timezone` varchar(16) null,
		`avatar` varchar(255) null
	);";
	$sql = sqlite2mysql($sql) if setting('plugins')->{Database}->{driver} eq 'mysql';
	database()->do($sql) or die database()->errstr;
}
sub sqlite2mysql {
	my $sql = shift;

	$sql =~ s/AUTOINCREMENT/AUTO_INCREMENT/;

	return $sql;
}

Dancer::Logger::debug("Setting up route '$conf->{route_login}' \t\tfor login()");
any ['get', 'post'] => $conf->{route_login} => sub {
	my $err;

	if ( request->method() eq "POST" ) {
		## check if nickname exists
		my $users = database()->prepare("SELECT id,nickname,password FROM users WHERE nickname = ?; ") or error database()->errstr;
		$users->execute( params->{'nickname'} );
		my $user = $users->fetchrow_hashref;	# with SQLite, rows is only available after fetchrow

		if( ! $users->rows ){
			$err = "Unknown user";
		}
		elsif( ! passphrase( param('password') )->matches( $user->{password} ) ){
			$err = "Invalid password";
		}
		else {
			session 'user' => {
				id		=> $user->{id},
				nickname	=> $user->{nickname},
			};
			return redirect "/user/$user->{id}";
		}
	}

	# display login form
	template 'login.tt', {
		err		=> $err,
		title		=> 'Login',
	};
};


Dancer::Logger::debug("Setting up route '$conf->{route_openid_login}' \tfor openid_login()");
any ['get', 'post'] => $conf->{route_openid_login} => sub {
	my $err;

	if( param('returning') ){
		Dancer::Logger::debug("/openid_login: returning user: ".Dumper( scalar(params()) )) if config->{log} eq 'debug';
		my $csr = Net::OpenID::Consumer->new(
			ua		=> LWPx::ParanoidAgent->new( timeout => 10, agent => 'libwww-perl/'. $LWP::UserAgent::VERSION . '+' . __PACKAGE__.'/'.$VERSION ),
		#	cache		=> Cache::File->new( cache_root => '/tmp/mycache' ),
			args		=> scalar( params() ),
			consumer_secret	=> Digest::SHA1::sha1_hex( config->{appdir} .'OpenID' ),
			required_root	=> request->base,
			assoc_options	=> [
				max_encrypt => 1,
			#	session_no_encrypt_https => 1,
			],
		);

		if($csr->is_server_response){
			if($csr->setup_needed){
				# (OpenID 2) retry request in checkid_setup mode
				# (OpenID 1) redirect/link/popup user to $csr->user_setup_url
				$err = 'Error code "setup_needed". Please contact the administrator with this error code';
			}elsif($csr->user_cancel){
				$err = 'User hit cancel';
			}elsif(my $verified_identity = $csr->verified_identity){
				my $verified_url = $verified_identity->url;
				Dancer::Logger::debug('/openid_login: successfully verified user display:'.$verified_identity->display .', identity:'.$verified_identity->{identity});

				## check if nickname exists
				my $users = database()->prepare("SELECT id,nickname,password FROM users WHERE openid_identity = ?; ") or error database()->errstr;
				$users->execute( $verified_identity->{identity} );
				my $user = $users->fetchrow_hashref;	# with SQLite, rows is only available after fetchrow

				if( $users->rows ){
					session 'user' => {
						id		=> $user->{id},
						nickname	=> $user->{nickname},
						openid		=> $verified_identity->{identity},
					};
					return redirect "/user/$user->{id}";
				}else{			
					my $sreg = $verified_identity->extension_fields('http://openid.net/extensions/sreg/1.1');

					my $openid = {
						verified	=> 1,
						identity	=> $verified_identity->{identity},
						display		=> $verified_identity->display,
						nickname	=> $sreg->{nickname},
						email		=> $sreg->{email},
						fullname	=> $sreg->{fullname},
						dob		=> $sreg->{dob},
						gender		=> $sreg->{gender},
						postcode	=> $sreg->{postcode},
						country		=> $sreg->{country},
						language	=> $sreg->{language},
						timezone	=> $sreg->{timezone},
						avatar		=> $sreg->{avatar},
					};

					forward($conf->{route_openid_register}, { openid => $openid } );
				}
			}else{
				$err = 'Error validating identity: '. $csr->err;
			}
		}else{
		      $err = 'Your OpenId provider didn\'t return an OpenID message';
		}
	}elsif ( request->method() eq "POST") {
		if( param('openid_url') ){
			my $csr = Net::OpenID::Consumer->new(
				ua		=> LWPx::ParanoidAgent->new,
			#	cache		=> Cache::File->new( cache_root => '/tmp/mycache' ),
			#	args		=> undef,
				consumer_secret	=> Digest::SHA1::sha1_hex( config->{appdir} .'OpenID' ),
				required_root	=> request->base,
				assoc_options	=> [
					max_encrypt => 1,
				#	session_no_encrypt_https => 1,
				],
			);

			Dancer::Logger::debug("/openid_login: issuing OpenID claimed_identity request");
			my $claimed_identity = $csr->claimed_identity( param('openid_url') );
			if($claimed_identity) {
				Dancer::Logger::debug("/openid_login: OpenID claimed_identity request OK");

				$claimed_identity->set_extension_args(
					'http://openid.net/extensions/sreg/1.1',
					{
					#	required => '',
						optional => 'nickname,email,fullname,dob,gender,postcode,country,language,timezone,avatar',
						policy_url => request->uri_base .'/terms#privacy'
					},
				);

				my $check_url = $claimed_identity->check_url(
					return_to	=> request->uri_base .'/openid_login?returning=1',
					trust_root	=> request->base,
					delayed_return	=> 1,
				);
				Dancer::Logger::debug("/openid_login: user redirected to OpenID provider...");
				return redirect $check_url;
			}else{
				$err = "This OpenId seems to be invalid! ". $csr->err;
			}
		}else{
			$err = 'No OpenID URL supplied!';
		}
	}

	# display login form
	template 'openid_login', {
		err		=> $err,
		title		=> 'OpenID Login',
	};
};


Dancer::Logger::debug("Setting up route '$conf->{route_logout}' \t\tfor logout()");
get $conf->{route_logout} => sub {
	session->destroy;
	session->flush; # needed for Session::Cookie to propagate the destroy()
	redirect '/';
};


Dancer::Logger::debug("Setting up route '$conf->{route_register}' \t\tfor register()");
any ['get', 'post'] => $conf->{route_register} => sub {
	my @err;

	if ( request->method() eq "POST" ) {
		## check if nickname length is ok
		if( length(param('nickname')) < 3 || length(param('nickname')) > 25 ){
			push(@err, 'Username lenght has to be between 3 and 25 characters.');
		}
		## check if nickname is valid
		if( param('nickname') =~ /\s+/ ){
			push(@err, 'Space is not allowed in usernames.');
		}
		if( $conf->{reserved_logins} && param('nickname') =~ $conf->{reserved_logins_regex} ){
			push(@err, 'This is a reserved username.');
		}

		## check if nickname exists
		my $users = database()->prepare("SELECT nickname FROM users WHERE nickname = ?; ") or error database()->errstr;
		$users->execute( param('nickname') );
		$users->fetchrow_hashref;	# with SQLite, rows is only available after fetchrow

		if( $users->rows ){
			push(@err,'Username '. param('nickname') .' is taken. Sorry.');
		}

		## check if password is long enough
		if( length(param('password')) < 6 ){
			push(@err, 'Passwords must be at least 6 characters long.');
		}
		## check if password is too weak
		if( param('password') =~ /^12345|^password$|^iloveyou$|^abc123|^123abc|^princess$|^nicole$|^dancer$|^rockyou$|^babygirl$|^monkey$|^qwerty$|^qwertz$|^letmein$/ ){
			push(@err, 'Please choose a stronger password.');
		}

		## if all checks succeed, insert new user and redirect
		if(!@err){
			Dancer::Logger::debug("/register: adding user ".params->{nickname});
			my $users = database()->prepare("INSERT INTO users (nickname,password) VALUES (?,?) ; ") or error database()->errstr;
			$users->execute( param('nickname'), passphrase( param('password') )->generate()->rfc2307() );
			my $user_id = setting('plugins')->{Database}->{driver} eq 'mysql' ? database()->{'mysql_insertid'} : database()->sqlite_last_insert_rowid();

			## log user in
			session 'user' => {
				id		=> $user_id,
				nickname	=> param('nickname'),
			};

			return redirect '/user/'.$user_id;
		}
	}

	# display registration form
	template 'register' => {
		'err'	=> join("<br>",@err),
		title	=> 'Register',
		nickname => param('nickname'),
		user	=> session('user'),
	};
};


Dancer::Logger::debug("Setting up route '$conf->{route_openid_register}' \tfor openid_register()");
any ['get', 'post'] => $conf->{route_openid_register} => sub {
	if( param('openid') && param('openid')->{verified} ){
		session 'openid' => param('openid');	## sadly, we couldn't set session earlier, as it doesn't persist over forward()
	}elsif( session('openid') && session('openid')->{verified} ){
		# ok
	}else{
		return 'Forbidden';
	}

	my @err;

	if ( request->method() eq "POST" ) {
		## check if nickname length is ok
		if( length(param('nickname')) < 3 || length(param('nickname')) > 25 ){
			push(@err, 'Username lenght has to be between 3 and 25 characters.');
		}
		## check if nickname is valid
		if( param('nickname') =~ /\s+/ ){
			push(@err, 'Space is not allowed in usernames.');
		}
		if( $conf->{reserved_logins} && param('nickname') =~ $conf->{reserved_logins_regex} ){
			push(@err, 'This is a reserved username.');
		}

		## check if nickname exists
		my $users = database()->prepare("SELECT nickname FROM users WHERE nickname = ?; ") or error database()->errstr;
		$users->execute( param('nickname') );
		$users->fetchrow_hashref;	# with SQLite, rows is only available after fetchrow

		if( $users->rows ){
			push(@err,'Username '. param('nickname') .' is taken. Sorry.');
		}

		## if all checks succeed, insert new user and redirect
		if(!@err){
			Dancer::Logger::debug('/openid_register: adding OpenID user:'.Dumper(session('openid'))) if config->{log} eq 'debug';
			my $so = session('openid');
			my $users = database()->prepare("INSERT INTO users (openid_identity,nickname,email,fullname,dob,gender,postcode,country,language,timezone,avatar) VALUES (?,?,?,?,?,?,?,?,?,?,?) ; ") or error database()->errstr;
			$users->execute( $so->{identity}, param('nickname'), $so->{email},$so->{fullname},$so->{dob},$so->{gender},$so->{postcode},$so->{country},$so->{language},$so->{timezone},$so->{avatar} );
			my $user_id = setting('plugins')->{Database}->{driver} eq 'mysql' ? database()->{'mysql_insertid'} : database()->sqlite_last_insert_rowid();

			## log user in
			session 'user' => {
				id		=> $user_id,
				nickname	=> param('nickname'),
			};

			return redirect '/user/'.$user_id;
		}
	}

	# display registration form
	template 'openid_register' => {
		'err' => join("<br>",@err),
		title	=> 'OpenID Registration',
		nickname=> param('openid')->{nickname} ? param('openid')->{nickname} : param('openid')->{display},
		user	=> session('user'),
	};
};


Dancer::Logger::debug("Setting up route '$conf->{route_end_membership}' \tfor end_membership()");
any ['get', 'post'] => $conf->{route_end_membership} => sub {
	forward $conf->{route_login} unless session('user');

	my $session_user = api_get_user( session('user')->{id} );

	if ( request->method() eq "POST" && param('confirmed') ) {
		api_delete_user($session_user->{id});
		session->destroy;
		session->flush; # needed for Session::Cookie to propagate the destroy()
	}

	template 'end_membership' => {
		title		=> 'End your membership',
		confirmed	=> param('confirmed'),
	};
};


register_plugin;
1;

__END__

=head1 NAME

Dancer::Plugin::Users - Adds user logic, routines and OpenID auth to Dancer apps

=head1 SYNOPSIS

	use Dancer::Plugin::Users;

=head1 DESCRIPTION

This module adds one flavour of basic logic and routes it needs to enable users
of your web application to register, log in and out and end their association.

As bonus, it also offers L<OpenID|http://en.wikipedia.org/wiki/OpenID> logins! Yay!

For all the Why & How, you might also want to check out the L<thread of the original pull-request|https://github.com/PerlDancer/Dancer/pull/829>
this module is based on, in addition to the "background" section further down.

=head1 DATABASE & SESSION

The plugin assumes that L<Dancer::Plugin::Database> is in use and some other
plugin is offering a session() store. Upon app startup, Dancer::Plugin::Users will
connect to database table 'users', which is created if it doesn't exist.

=head1 ROUTES

The module adds six routes to your application, hardcoded. Although you can change
their URLs from the config files:

	/login
	/openid_login
	/logout
	/register
	/openid_register
	/end_membership

Each route relies on a template of the same name. The examples folder in this package
should have some basic templates for you to start from.

=head1 CONFIGURATION

In config files, you can set these variables:

	plugins:
	  Users:
	    route_login: "/login"
	    route_openid_login: "/openid_login"
	    route_logout: "/logout"
	    route_register: "/register"
	    route_openid_register: "/openid_register"
	    route_end_membership: "/end_membership"
	    reserved_logins: "admin root superuser demo Anonymous test"	  # space separated, case-insensitive
	    db_table: "users"

The example also shows the defaults, so all this can be left out if these are okay for you.

=head1 USAGE

In templates, for example:

	<% IF session.user.id %>
		Hello <a href="/user/<% session.user.id %>"><% session.user.nickname %></a> | <a href="/user/<% session.user.id %>">My profile</a> | <a href="/logout">logout</a>
	<% ELSE %>
		<a href="/login" rel="nofollow">login</a> . <a href="/register" rel="nofollow">register</a>
	<% END %>

In your route's code:

	# This is what's done after a sucessful login
	session 'user' => {
		id		=> $user->{id},
		nickname	=> $user->{nickname},
		openid		=> $verified_identity->{identity}, # only on openID logins
	};

	# add this somewhere to check if a visitor is logged-in
	forward '/login' unless session('user');

=head1 BACKGROUND

I took inspiration from the audacity of L<Locale::Wolowitz> to do something in
'yet another way'. The result is a wild blend of what would normally end up in more
focused, separate modules, probably within the ::Auth or some user management namespace - 
only here, it's all packaged in one single (light) module that 'simply works'.

It's meant less to be a well thought out authentication module, or a complete user
management add-on, and is far from being a framework. It's more a set of common
practices, routines and tools I tend to throw-in when I build webapps that know
about the concepts of "users" and "logins". As such, it doesn't come with ready-built
templates, (as you'd have to customise them anyway), it makes a few assumtions
about application flow and is not fully configurable. Sorry for that. It's just
what looks sane to me. Anyway, I share it here as it may be of use for like-minded
developers, and it's handy to have it up on GitHub. Yes, read that again, GitHub 
only for now, as reserving the Dancer::Plugin::Users namespace might be a bit too
audacious.

=head1 BUGS & CAVEATS

As I think the default configuration is the most practical, that's what I
use and that's the proven one. As a result, changing settings is not that well tested.

The database currently holds only one OpenID peer. That might be a limitation if
you want to offer your users multiple OpenID authorities to log into a single account
on your webapp. 

In case you found anything obvious to fix/change/improve, feel free to contribute
on github.

=head1 SEE ALSO

For completeness, last time I looked, these authentication-related Dancer plugins
were on CPAN:
L<Dancer::Plugin::Auth::Extensible>, L<Dancer::Plugin::Auth::RBAC>, L<Dancer::Plugin::Auth::Twitter>,
L<Dancer::Plugin::Auth::Github>, L<Dancer::Plugin::Authen::Simple>, L<Dancer::Plugin::Facebook>,
L<Dancer::Auth::GoogleAuthenticator>

=head1 COPYRIGHT & LICENSE

This library is free software; you can redistribute it and/or modify it under the same terms as Perl itself
