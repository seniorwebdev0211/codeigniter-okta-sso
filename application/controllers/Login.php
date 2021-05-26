<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Login extends CI_Controller {

    public function __construct() {           
        parent::__construct();
             
        require_once FCPATH . 'vendor/autoload.php';

        $dotenv = Dotenv\Dotenv::createImmutable(FCPATH);
        $dotenv->load();

        $this->load->helper('url');
    }

    private function exchangeCode($code) {
        $authHeaderSecret = base64_encode( $_ENV['CLIENT_ID'] . ':' . $_ENV['CLIENT_SECRET'] );
        $query = http_build_query([
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $_ENV['REDIRECT_URI']
        ]);
        $headers = [
            'Authorization: Basic ' . $authHeaderSecret,
            'Accept: application/json',
            'Content-Type: application/x-www-form-urlencoded',
            'Connection: close',
            'Content-Length: 0'
        ];
        $url = $_ENV["ISSUER"].'/v1/token?' . $query;
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_HEADER, 0);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_POST, 1);
        $output = curl_exec($ch);
        $httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if(curl_error($ch)) {
            $httpcode = 500;
        }
        curl_close($ch);
        return json_decode($output);
    }

    private function verifyJwt($jwt)
    {
        try {
            $jwtVerifier = (new \Okta\JwtVerifier\JwtVerifierBuilder())
                ->setAdaptor(new \Okta\JwtVerifier\Adaptors\FirebasePhpJwt)
                ->setIssuer($_ENV['ISSUER'])
                ->setAudience('api://default')
                ->setClientId($_ENV['CLIENT_ID'])
                ->build();
    
            return $jwtVerifier->verify($jwt);
        } catch (\Exception $e) {
            echo $e;
            return false;
        }
    }
        
    private function isAuthenticated()
    {
        if(isset($_COOKIE['access_token'])) {
            return true;
        }

        return false;
    }

    private function getProfile()
    {
        if(!$this->isAuthenticated()) {
            return [];
        }

        $jwtVerifier = (new \Okta\JwtVerifier\JwtVerifierBuilder())
            ->setAdaptor(new \Okta\JwtVerifier\Adaptors\FirebasePhpJwt)
            ->setIssuer($_ENV['ISSUER'])
            ->setAudience('api://default')
            ->setClientId($_ENV['CLIENT_ID'])
            ->build();

        $jwt = $jwtVerifier->verify($_COOKIE['access_token']);

        return $jwt->claims;

    }

	public function index()
	{
        $query = http_build_query([
            'client_id' => $_ENV['CLIENT_ID'],
            'response_type' => 'code',
            'response_mode' => 'query',
            'scope' => 'openid profile',
            'redirect_uri' => $_ENV['REDIRECT_URI'],
            'state' => $_ENV['STATE']
        ]);

        header('Location: ' . $_ENV["ISSUER"].'/v1/authorize?'.$query);
	}

    public function authorize_callback() {
        if(array_key_exists('state', $_REQUEST) && $_REQUEST['state'] !== $_ENV['STATE']) {
            throw new \Exception('State does not match.');
        }

        if(array_key_exists('code', $_REQUEST)) {
            $exchange = $this->exchangeCode($_REQUEST['code']);
            if(!isset($exchange->access_token)) {
                die('Could not exchange code for an access token');
            }

            if($this->verifyJwt($exchange->access_token) == false) {
                die('Verification of JWT failed');
            }

            setcookie("access_token", "$exchange->access_token", time()+$exchange->expires_in, "/", false);
            redirect('/dashboard', 'location');
        }

        die('An error during login has occurred');
    }
    
	public function dashboard()
	{
        if (!$this->isAuthenticated()) {
            redirect('/', 'location');
        }

        // Get Profile
        $data['profile'] = $this->getProfile();

        $this->load->view('dashboard', $data);
	}

    public function logout() {
        setcookie("access_token",NULL,-1,"/",false);
        redirect('/', 'location');
    }
}
