var querystring = require('querystring');
var cookie_name = querystring.parse(process.env.CLIENT_COOKIE,';').name;
var input = '';
var input_name = '';
var output = '';
var name_cookie = '';

process.stdin.on('readable', function() {
	var new_data = process.stdin.read();
	if (new_data !== null) {
		input += new_data;
	}
});

process.stdin.on('end', process_input_and_name);

function process_input_and_name() {
	if (input) {
		input_name = querystring.parse(input).name;
		if (input_name) {
			if (input_name.length < 30) {
				add_to_output('Okay, hi '+input_name+'! Good to meet you.\n\n');
				add_to_output('If I got your name wrong, sorry! Please tell me again.\n\n');
				set_name(input_name);
			}
			else {
				add_to_output("Sorry, that's way too long for me to remember! Try a shorter one?\n\n");
			}
		}
		else {
			add_to_output("I didn't quite catch that. Could you repeat yourself, please?\n\n");
		}
	}
	else if (cookie_name) {
		add_to_output('Hello again '+cookie_name+'!\n\nTell me if your name changed.\n\n');
	}
	else {
		add_to_output("Hm. I don't seem to know who you are.\n\n");
		add_to_output("Who are you?\n\n");
	}
	writeform();
	
	process.stdout.write(JSON.stringify({cookie:name_cookie, body:output}));
}

function writeform() {
	add_to_output('<form action="index" method="POST">');
	add_to_output('<input type="text" name="name"/>');
	add_to_output('<input type="submit" value="Submit"/></form>');
}

function add_to_output(s) {
	output += s;
}

function set_name(name) {
	name_cookie = "Set-cookie: name="+encodeURIComponent(name);
}

