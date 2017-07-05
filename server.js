/**
 * Simple authentication and authorization example with passport, node_acl,
 *  MongoDB and expressjs
 *
 * The example shown here uses local userdata and sessions to remember a
 *  logged in user. Roles are persistent all the way and applied to user
 *  after logging in.
 *
 * Usage:
 *  1. Start this as server
 *  2. Play with the resoures
 *
 *     Login via GET
 *      http://localhost:3500/login?username=bob&password=secret
 *
 *     Logout
 *      http://localhost:3500/logout
 *
 *     Check your current user and roles
 *      http://localhost:3500/status
 *
 *     Only visible for users and higher
 *      http://localhost:3500/secret
 *
 *     Manage roles
 *     user is either 1 or 2 and role is either 'guest', 'user' or 'admin'
 *      http://localhost:3500/allow/:user/:role
 *      http://localhost:3500/disallow/:user/:role
 */

var express = require( 'express' ),
    mongodb = require( 'mongodb' ),
    passport = require( 'passport' ),
    node_acl = require( 'acl' ),
    app = express(),
    localStrategy = require( 'passport-local' ).Strategy,
    acl;

// Some test data. Get this from your database.
var users = [
    { id: 1, username: 'bob', password: 'secret', email: 'bob@example.com' },
    { id: 2, username: 'joe', password: 'birthday', email: 'joe@example.com' }
];


app.use(require('cookie-parser')());
app.use(require('body-parser').urlencoded({ extended: true }));
app.use(require('express-session')({
  secret: 'keyboard cat',
  resave: true,
  saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());

// Error handling
app.use( function( error, request, response, next ) {
    if( ! error ) {
        return next();
    }
    response.send( error.msg, error.errorCode );
});

authentication_setup();

// Connecting to mongo database and setup authorization
mongodb.connect( 'mongodb://127.0.0.1:27017/acl', authorization_setup );

// Setting up passport
function authentication_setup() {

    // Setup session support
    passport.serializeUser( function( user, done ) {
        done( null, user.id );
    });

    passport.deserializeUser( function( id, done ) {
        find_user_by_id( id, function ( error, user ) {
           done( error, user );
        });
    });

    // Setup strategy (local in this case)
    passport.use( new localStrategy(
        function( username, password, done ) {
            process.nextTick( function () {
                find_by_username( username, function( error, user ) {

                    if ( error ) {
                        return done( error );
                    }

                    if ( ! user ) {
                        return done( null, false, { message: 'Unknown user ' + username } );
                    }

                    if ( user.password != password ) {
                        return done( null, false, { message: 'Invalid password' } );
                    }

                    // Authenticated
                    return done( null, user );
                });
            });
        }
    ));
}

// Setting up node_acl
function authorization_setup( error, db ) {

    // var mongoBackend = new node_acl.mongodbBackend( db /*, {String} prefix */ );
    acl = new node_acl(new node_acl.memoryBackend(), logger());
    // Create a new access control list by providing the mongo backend
    //  Also inject a simple logger to provide meaningful output
    // acl = new node_acl( mongoBackend, logger() );

    // Defining roles and routes
    set_roles();
    set_routes();
}

// This creates a set of roles which have permissions on
//  different resources.
function set_roles() {

    // Define roles, resources and permissions
    acl.allow([
        {
            roles: 'admin',
            allows: [
                { resources: '/secret', permissions: '*' }
            ]
        }, {
            roles: 'user',
            allows: [
                
            ]
        }, {
            roles: 'guest',
            allows: []
        }
    ]);

    // Inherit roles
    //  Every user is allowed to do what guests do
    //  Every admin is allowed to do what users do
    
    /**
     * Define Some Static roles here.
     */
    acl.addUserRoles(1,'user');
    acl.addUserRoles(2, 'admin');


    acl.addRoleParents( 'user', 'guest' );
    acl.addRoleParents( 'admin', 'user' );
}

// Defining routes ( resources )
function set_routes() {

    // Check your current user and roles
    app.get( '/status', function( request, response ) {
        acl.userRoles( get_user_id( request, response ), function( error, roles ){
            response.send( 'User: ' + JSON.stringify( request.user ) + ' Roles: ' + JSON.stringify( roles ) );
        });
    });

    // Only for users and higher
    app.get( '/secret',
        // Actual auth middleware
        [ authenticated, acl.middleware() ],
        function( request, response ) {
            response.send( 'Welcome Sir!' );
        }
    );

    // Logging out the current user
    app.get( '/logout', function( request, response ) {
        request.logout();
        response.send( 'Logged out!' );
    });

    // Logging in a user
    //  http://localhost:3500/login?username=bob&password=secret
    app.get( '/login',
        passport.authenticate( 'local', {} ),
        function( request, response ) {
            console.log(request.user);
            response.send( 'Logged in!' );

        }
    );

    // Setting a new role
    app.get( '/allow/:user/:role', function( request, response, next ) {
        acl.addUserRoles( request.params.user, request.params.role );
        response.send( request.params.user + ' is a ' + request.params.role );
    });

    // Unsetting a role
    app.get( '/disallow/:user/:role', function( request, response, next ) {
        acl.removeUserRoles( request.params.user, request.params.role );
        response.send( request.params.user + ' is not a ' + request.params.role + ' anymore.' );
    });
}

// This gets the ID from currently logged in user
function get_user_id( request, response ) {

    // Since numbers are not supported by node_acl in this case, convert
    //  them to strings, so we can use IDs nonetheless.
    return request.user && request.user.id.toString() || false;
}

// Helper used in session setup by passport
function find_user_by_id( id, callback ) {

    var index = id - 1;

    if ( users[ index ] ) {
        callback( null, users[ index ] );
    } else {
        var error = new Error( 'User does not exist.' );
        error.status = 404;
        callback( error );
    }
}

// Helper used in the local strategy setup by passport
function find_by_username( username, callback ) {

    var usersLength = users.length,
        i;

    for ( i = 0; i < usersLength; i++ ) {
        var user = users[ i ];
        if ( user.username === username ) {
            return callback( null, user );
        }
    }

    return callback( null, null );
}

// Generic debug logger for node_acl
function logger() {
    return {
        debug: function( msg ) {
            console.log( '-DEBUG-', msg );
        }
    };
}

// Authentication middleware for passport
function authenticated( request, response, next ) {

    if ( request.isAuthenticated() ) {
        return next();
    }

    response.send( 401, 'User not authenticated' );
}

app.listen( 3500, function() {
    console.log( 'Express server listening on port 3500' );
});