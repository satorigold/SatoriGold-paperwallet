var getStringWords = function(string) {
  return string.replace(/^\s*(.*)\s*$/, '$1').replace(/\s+/, ' ').split(' ');
};

var genkeys = function(additional_entropy, lang) {
  var seed = cnUtil.sc_reduce32(poor_mans_kdf(additional_entropy + cnUtil.rand_32()));
  var keys = cnUtil.create_address(seed);
  var passPhrase = mn_encode(seed, lang);
  return {
    keys: keys,
    mnemonic: passPhrase
  }
};

//verify words of seed-phrase, for specified lang.
var verifyMnemonicSeedWords = function(seed_phrase, lang){	//seed_phrase, and lang (mnemonic prase dictionary, language)
	var words = [];									//define array with words
	if(seed_phrase.indexOf(' ') !== -1){			//if seed_phrase contains at lease 1 whitespace
		words = seed_phrase.split(' ');				//split this into array with words
		words.filter(function(e){return e});		//remove empty values
		if(words.length !== 25){ return false; }	//if not 25 words in array - invalid mnemonic seed
		
		var is_correct_english_mnemonic = 		//for english mnemonic seed-phrase - only
			(
				(
						/^[a-z\s]+$/.test(seed_phrase)					//seed phrase contains only lower-cased english letters from "a" to "z", and whitespaces (\s)
//					||	/^[A-Z\s]+$/.test(seed_phrase)					//or UPPER-CASED
//					||	/^[a-zA-Z\s]+$/.test(seed_phrase)				//or Upper-Lower-Cased
				)
				&&	words.length === 25									//and if, after splitting by ' ', (filtered array).length === 25...
			)															//return true or false
		;

		if(												//if
				!is_correct_english_mnemonic			//no
			&&	(lang === 'english')					//and lang is english
		){
			return false;									//this is not correct english mnemonic - return false.
		}
		else{											//else, mnemonic is correct, or another lang was specified
			for(var i = 0; i<words.length; i++){		//then, for each word
				if(											//if
					(
						(
							mn_words[lang]					//in mn_words object, for specified langth
						)
						.words								//in words array
					)
					.indexOf(								//index of
						words[i]							//the current word
					)
					===										//is equal of
					-1										//-1
				){											//current word does not exist in array
					return false;							//so mnemonic seed is invalid - return false
				}
			}
		}
		return true;								//else if all words contains there - mnemonic seed is valid, return true.
	}
	return false;									//else - this was not been a mnemonic seed, because no any whitespase - return false.
}

var custom_password = custom_password || 'super-secret password to change seeds from the same keywords';
//This password need just to get different seed from the same phrase.
//Change this password, for your own brainwallet, which can working locally.


//restore keys
//			from "mnemonic seed-phrase", with differet "lang" (need to select the correct "lang"-value, by default - "english"-words)
//		or	from Spend privateKey-hex (32 bytes),
//		or  from seed-hex, as any 32 bytes, 64 hexadecimal characters (this value will be reduced to Spend privateKey-hex),
//		or	from custom brainwallet-value, phrase or words
//				(
//					this brainwallet-value + custom_password (can be changed in code) = brainwallet,
//					and seed_hex = sha256( sha256(brainwallet-value) + sha256(custom_password) )
//					and spendKey = reduce_sk(seed_hex) //seed_hex, reduced to spendKey
//				)
var restore_keys = function(seed_phrase, lang) {
  seed_phrase = seed_phrase || document.getElementById("seed_phrase").value;	//use seed-phrase if this specified, as param, or extract this from input
//  console.log('seed_phrase', seed_phrase);

  var seed;    //define this variable to set seed value of this. Seed this is some 32 bytes hex, reduced to Spend privkey.
  var is_correct_mnemonic = verifyMnemonicSeedWords(seed_phrase, lang);		//true/false.

  if(													//if 		- mnemonic
		is_correct_mnemonic === true		//if this was been correct mnemonic seed-phrase
  ){
		seed = mn_decode(seed_phrase, lang);						//Decode this to seed-hex.
//		console.log('seed from mnemonic', seed);
  }
  else if(													//else if
		is_correct_mnemonic === false
	&&	seed_phrase.indexOf(' ') !== -1							//1 whitespace(s) exists
	&&	seed_phrase.split(' ').length === 25					//and 25 words in array, after split by whitespace
  ){	//this seems, like mnemonic, but first if returned false.
	
	document.getElementById("seed_phrase").value = ('Select the correct lang-value (dictionary) in the top.');	//show this notification...
	document.getElementById("seed_phrase").style.borderColor="red";												//add red border to input, as warning.
	
	setTimeout(																		//then, by timeout
		function(){
			document.getElementById("seed_phrase").style.borderColor="initial";		//turn it back
			document.getElementById("seed_phrase").value = seed_phrase;				//with previous seed-phrase
		},
		5000																		//after 5 seconds
	);
	return false;																	//and do not continue the process, but "return false".
  }
  else if(												//else if 	- any hex with 32 bytes (64 chars)
			/^[0-9a-fA-F]{64}$/i.test(seed_phrase)			//this was been specified a hex, with digits 0-9 and abcdef (lowercased or/and UpperCased too),
															//and if length is 64 hexadecimal characters (32 bytes)
  ){
		seed = seed_phrase;									//this seems like a seed, and just use this as seed.
		seed = cnUtil.sc_reduce32(seed);					//then, just reduce this seed to correct spendKey hex.
//		console.log('seed as hex', seed);
  }
  else{													//else, if	- brainwallet		(means if "seed_phrase", contains the some another data)
//		seed = cnUtil.sc_reduce32(poor_mans_kdf(sha256(seed_phrase) + sha256(custom_password)));

		var sha256hash = sha256(seed_phrase);							//compute sha256hash from this
		var combined_string = ( sha256hash + sha256(custom_password) )	//combine with sha256hash of custom password, to derive seed-hex.
		seed = sha256(combined_string);									//then, compute sha256 hash from this combined hex, to get hexadecimal seed
		seed = cnUtil.sc_reduce32(seed);								//and then, just reduce this seed to correct spendKey-hex.
		//Now, seed - this is correct seed, and spendKey-hex.

//		console.log('seed brainwallet', seed);
  }

  //generate keys from seed, where seed is privateKey.
  var keys = cnUtil.create_address(seed);								//get address from "seed"
  
//  console.log('keys', keys);

	//show this.
  address_widget.innerHTML = keys.public_addr;
  mnemonic_widget.innerHTML = ( ( is_correct_mnemonic ) ? seed_phrase : mn_encode(seed, lang));		//show mnemonic seed as is, or compute this for specified lang.
  spend_key_widget.innerHTML = keys.spend.sec;
  view_key_widget.innerHTML = keys.view.sec;
};

//update config for custom coin
var updateConfig = function(){
	var newConfig = config || {};

	newConfig.addressPrefix		=		parseInt(	document.getElementById("addressPrefix").value	, 10	)	;
	newConfig.coinName			=					document.getElementById("coinName").value					;
	newConfig.coinSymbol		=					document.getElementById("coinSymbol").value					;
	newConfig.coinUnitPlaces	=		parseInt(	document.getElementById("coinUnitPlaces").value	, 10	) 	;
	newConfig.coinUriPrefix		=					document.getElementById("coinUriPrefix").value				;

	cnUtil.update_config(newConfig);
	genwallet(document.getElementById('mnDictLangValue').value);
};

var show_restore = function() {
  document.getElementById("restore").style.display = "block";
//  document.getElementById("generate").style.display = "none";
//  document.getElementById("step2").style.display = "none";
};

var genwallet = function(lang) {
  var spend_key_widget = document.getElementById("spend_key_widget");
  var view_key_widget = document.getElementById("view_key_widget");
  var address_widget = document.getElementById("address_widget");
  var address_qr_widget = document.getElementById("address_qr_widget");
  var user_entropy_widget = Math.floor(100000000 + Math.random() * 900000000);

  var res = genkeys(user_entropy_widget.value, lang);
  var keys = res.keys;
  var mnemonic = res.mnemonic;

  address_widget.innerHTML = keys.public_addr;
  mnemonic_widget.innerHTML = mnemonic;
  spend_key_widget.innerHTML = keys.spend.sec;
  view_key_widget.innerHTML = keys.view.sec;

  var typeNumber = 0;
  var errorCorrectionLevel = 'L';


  var qr = qrcode(typeNumber, errorCorrectionLevel);
  qr.addData(keys.public_addr);
  qr.make();
  document.getElementById('address_qr_widget').innerHTML = qr.createImgTag();


  var qr = qrcode(typeNumber, errorCorrectionLevel);
  qr.addData(keys.spend.sec);
  qr.make();
  document.getElementById('qrcodeSecret').innerHTML = qr.createImgTag();

  var qr = qrcode(typeNumber, errorCorrectionLevel);
  qr.addData(keys.view.sec);
  qr.make();
  document.getElementById('qrcodeView').innerHTML = qr.createImgTag();


};

var hide_for_print = function(){
	document.getElementById('additional_params').style.display='none';
	document.getElementById('buttons').style.display='none';
	document.getElementById('zip_link').innerText='Download this as zip-archive: https://github.com/satorigold/SatoriGold-paperwallet/archive/master.zip';
	setTimeout(
		function(){
			document.getElementById('additional_params').style.display='block';
			document.getElementById('buttons').style.display='block';
			document.getElementById('zip_link').innerText='Download this as zip-archive.';
		}
		,
		2000
	);
}
