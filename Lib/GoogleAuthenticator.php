<?php
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

App::uses('FixedBitNotation', 'GoogleAuthenticate.Lib');

class GoogleAuthenticator {

	static $PASS_CODE_LENGTH = 6;

	static $PIN_MODULO;

	static $SECRET_LENGTH = 10;

	public function __construct() {
		self::$PIN_MODULO = pow(10, self::$PASS_CODE_LENGTH);
	}

	public function checkCode($secret, $code, $type) {
                switch ($type) {
                    case 'google':
                        $time = floor(time() / 30);
                        for ($i = -1; $i <= 1; $i++) {
                                if ($this->getCode($secret, $time + $i) == $code) {
                                        return true;
                                }
                        }
                        return false;
                        break;
                    case 'feitian': 
                        $time = floor(time() / 60);
                        for ($i = -1; $i <= 1; $i++) {
                                if ($this->getCodeFeitian($secret, $time + $i) == $code) {
                                        return true;
                                }
                        }
                        return false;
                        break;
                    default:
                        return false;
                        break;
                }
	}

	public function getCode($secret, $time = null) {
		if (!$time) {
			$time = floor(time() / 30);
		}
		$base32 = new FixedBitNotation(5, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', true, true);
		$secret = $base32->decode($secret);

		$time = pack("N", $time);
		$time = str_pad($time, 8, chr(0), STR_PAD_LEFT);

		$hash = hash_hmac('sha1', $time, $secret, true);
		$offset = ord(substr($hash, -1));
		$offset = $offset & 0xF;

		$truncatedHash = self::hashToInt($hash, $offset) & 0x7FFFFFFF;
		$pinValue = str_pad($truncatedHash % self::$PIN_MODULO, 6, "0", STR_PAD_LEFT);
		return $pinValue;
	}
        
        public function getCodeFeitian($secret, $time = null) {
		if (!$time) {
			$time = floor(time() / 60);
		}
		
		$time = pack("N", $time);
		$time = str_pad($time, 8, chr(0), STR_PAD_LEFT);

		$hash = hash_hmac('sha1', $time, hex2bin($secret), true);
		$offset = ord(substr($hash, -1));
		$offset = $offset & 0xF;

		$truncatedHash = self::hashToInt($hash, $offset) & 0x7FFFFFFF;
		$pinValue = str_pad($truncatedHash % self::$PIN_MODULO, 6, "0", STR_PAD_LEFT);
		return $pinValue;
	}

	protected function hashToInt($bytes, $start) {
		$input = substr($bytes, $start, strlen($bytes) - $start);
		$val2 = unpack("N", substr($input, 0, 4));
		return $val2[1];
	}

	public function getUrl($secret, $username, $hostname = null) {
		if ($hostname) {
			$username .= "@" . $hostname;
		}
		$data = "otpauth://totp/{$username}?secret={$secret}";
		return "https://chart.googleapis.​com/chart?chs=200x200&chld=M|0&cht=qr&chl={$data}";
	}

	public function generateSecret() {
		$secret = "";
		for ($i = 1; $i <= self::$SECRET_LENGTH; $i++) {
			$c = rand(0, 255);
			$secret .= pack("c", $c);
		}
		$base32 = new FixedBitNotation(5, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', true, true);
		return $base32->encode($secret);
	}

}