<?php
require_once( ABSPATH.'wp-admin/includes/user.php' ); 
require_once( ABSPATH . 'wp-admin/includes/image.php' );
require_once( ABSPATH . 'wp-admin/includes/file.php' ); 
require_once( ABSPATH . 'wp-admin/includes/media.php' );


/**
 *
 * @wordpress-plugin
 * Plugin Name: Creator Rest API
 * Description: Test.
 * Version: 1.0
 * Author: Kanishk
**/ 

use Firebase\JWT\JWT;
use \Firebase\JWT\Key;

class Custom_API extends WP_REST_Controller {
    private $api_namespace;
	private $api_version;
	private $required_capability;
	public  $user_token;
	public  $user_id;
	
	public function __construct() {
		$this->api_namespace = 'addapi/v';
		$this->api_version = '1';
		$this->required_capability = 'read';
		$this->init();
		/*------- Start: Validate Token Section -------*/
		$headers = getallheaders(); 
		if(isset($headers['Authorization'])){ 
        	if(preg_match('/Bearer\s(\S+)/', $headers['Authorization'], $matches)){ 
            	$this->user_token =  $matches[1]; 
        	}
        }
        /*------- End: Validate Token Section -------*/
	}
    
	private function successResponse($message='',$data=array(),$total = array()){ 
        $response =array();
        $response['status'] = "success";
        $response['message'] =$message;
        $response['data'] = $data;
        if(!empty($total)){
            $response['pagination'] = $total;
        }
        return new WP_REST_Response($response, 200);  
    }
     
    public function errorResponse($message='',$type='ERROR' , $statusCode = 400){
        $response = array();
        $response['status'] = "error";
        $response['error_type'] = $type;
        $response['message'] =$message;
        return new WP_REST_Response($response, $statusCode); 
    }

    public function register_routes(){  
		$namespace = $this->api_namespace . $this->api_version;
		
	    $privateItems = array('getUserInfo', 'searchBrewery', 'getBreweryDetails', 'insertReview', 'getBreweryReviews'); //Api Name  and use to token
	    $publicItems  = array('signup'); //no needs for token 
		
		
		foreach($privateItems as $Item){
		    register_rest_route( $namespace, '/'.$Item, array( 
                'methods' => 'POST',    
                'callback' => array( $this, $Item), 
               'permission_callback' => !empty($this->user_token)?'__return_true':'__return_false' 
				//'permission_callback' => array( $this, 'isValidToken' ) // Ensure token is validated

                )  
	    	);  
		}
		foreach($publicItems as $Item){
		  	register_rest_route( $namespace, '/'.$Item, array(
                'methods' => 'POST',
                'callback' => array( $this, $Item )
                )
	    	);
		}
	}

	public function init(){
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
        // add_action('rest_api_init', 'add_custom_headers');
        add_action( 'rest_api_init', function() {
        remove_filter( 'rest_pre_serve_request', 'rest_send_cors_headers' );
            add_filter( 'rest_pre_serve_request', function( $value ) {
                header( 'Access-Control-Allow-Origin: *' );
                header( 'Access-Control-Allow-Methods: POST, GET, OPTIONS, PUT, DELETE' );
                header( 'Access-Control-Allow-Credentials: true' );
                // header("Access-Control-Allow-Headers: Content-Type");
                return $value;
            });
        }, 15 );
     
    }

    public function signup($request){
        global $wpdb;
        $param = $request->get_params();
        // $role  = 'customer';
    
        // Check if email is provided
        if(empty($param['email'])){
            return $this->errorResponse('Please provide email.');
        }
    
        // Check if email already exists
        if(email_exists($param['email'])){
            return $this->errorResponse('Email already exists.Please Login');
        }
    
        // Check if password and confirmPassword are provided and match
        if(empty($param['password']) || empty($param['confirmPassword'])){
            return $this->errorResponse('Please provide password and confirmPassword.');
        }
    
        if($param['password'] !== $param['confirmPassword']){
            return $this->errorResponse('Password does not match.');
        }

         // Check if role provided
        //  if(empty($param['role'])) {
        //     return $this->errorResponse('Please specify role');
        // }

         // Check if role provided
         if(empty($param['phone'])) {
            return $this->errorResponse('Please specify phone');
        }
         // Check if role provided
         if(empty($param['address'])) {
            return $this->errorResponse('Please specify address');
        }

            // Create user
        $user_id = wp_create_user($param['email'],$param['password'],$param['email']);
        if(is_wp_error($user_id)) {
            return $this->errorResponse($user_id->get_error_message());
        }

        $user = new WP_User($user_id);
        $user->set_role($param['role']);
    
        // Update user meta
        update_user_meta($user_id, 'name', $param['name']);
        update_user_meta($user_id, 'phone', $param['phone']);
        update_user_meta($user_id, 'address', $param['address']);
      
        // Get user profile data
        // $data = $this->getProfile($user_id);
    
        // Check if user was successfully registered
        if(!empty($user_id)){
            return $this->successResponse('User created successfully.', $user);
        } else {
            return $this->errorResponse('Something went wrong. Please try again later.', $user);
        }
    }
    
    private function isValidToken(){
    	$this->user_id  = $this->getUserIdByToken($this->user_token);
    }

    public function getUserIdByToken($token){
        $decoded_array = array();
        $user_id = 0;
        if($token){
            try{
                $decoded = JWT::decode($token, new Key(JWT_AUTH_SECRET_KEY, apply_filters('jwt_auth_algorithm', 'HS256')));
                $decoded_array = (array) $decoded;
            }catch(\Firebase\JWT\ExpiredException $e){
                return false;
            }
        }
        if(count($decoded_array) > 0){
            $user_id = $decoded_array['data']->user->id;
        }
        if($this->isUserExists($user_id)){
            return $user_id;
        }else{
            return false;
        }
    }

    public function isUserExists($user){
        global $wpdb;
        $count = $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM $wpdb->users WHERE ID = %d", $user));
        if ($count == 1) {return true;} else {return false;}
    }

    public function jwt_auth($data, $user){
		    $user_meta = get_user_meta($user->ID);
            $user_roles = $user->roles[0]; // Fetching roles from WP_User object
            // Get user roles
            $result = $this->getProfile($user->ID);
            $result['token'] =  $data['token'];
               return $this->successResponse('Successfully Logged In', $result);

       

        $code = $data['code'];

        if($code == '[jwt_auth] incorrect_password'){
            return $this->errorResponse('The password you entered is incorrect');
        }

        elseif($code == '[jwt_auth] invalid_email'  || $code == '[jwt_auth] invalid_username'){
            return $this->errorResponse('The email you entered is incorrect');
        }

		elseif($code == '[jwt_auth] empty_username'){
            return $this->errorResponse('The username field is empty.');
        }

        elseif($code == '[jwt_auth] empty_password'){
            return $this->errorResponse('The password field is empty.');
        }
		return $user;
    }

    public function getProfile($user_id){

        if (empty($user_id)) {
            return $this->errorResponse('Unauthorized', 'Unauthorized', 401);
        }

        $user = get_user_by('ID', $user_id);       

        $profile = array(
            'id' => $user->ID,
            'email' => $user->user_email,
            'name' => get_user_meta($user->ID, 'name', true),
            'phone' => get_user_meta($user->ID, 'phone', true),
            'address' => get_user_meta($user->ID, 'address', true)
            // 'roles' => $user->roles[0],
        );

        return $profile;
    
    }

    public function getUserInfo($request){
        global $wpdb;
        $param = $request->get_params();
        $this->isValidToken();
	    $user_id = !empty($this->user_id) ? $this->user_id : $param['user_id'];
		   
	    if (empty($user_id)) {
        return $this->errorResponse('Unauthorized', 'Unauthorized', 401);
        }
		else{
            $user_info = $this->getProfile($user_id);
            if($user_info){
                return $this->successResponse('Profile Data retrieved successfully', $user_info);
            }
            else{
                return $this->errorResponse('Failed to retrieve user profile.');
            }
        }
    }

    public function searchBrewery($request) {
        $param = $request->get_params();
        $query_params = [];
    
        // Handle name filter
        if (!empty($param['by_name'])) {
            $query_params['by_name'] = $param['by_name'];
        }
    
        // Handle type filter
        if (!empty($param['by_type'])) {
            $query_params['by_type'] = $param['by_type'];
        }
    
        // Handle city filter
        if (!empty($param['by_city'])) {
            $query_params['by_city'] = $param['by_city'];
        }
    
        // Set per_page and page for pagination
        $per_page = isset($param['per_page']) ? intval($param['per_page']) : 10;  // Default to 10 items per page
        $page = isset($param['page']) ? intval($param['page']) : 1;  // Default to page 1 if not provided
        $query_params['per_page'] = $per_page;
        $query_params['page'] = $page;
    
        // Construct the URL for Open Brewery DB API
        $url = 'https://api.openbrewerydb.org/v1/breweries?' . http_build_query($query_params);
    
        // Send the request to the Open Brewery DB API
        $response = wp_remote_get($url);
        $body = wp_remote_retrieve_body($response);
        $status_code = wp_remote_retrieve_response_code($response);
    
        // Check the response status
        if ($status_code == 200) {
            return $this->successResponse('Brewery search results.', json_decode($body, true));
        } else {
            return $this->errorResponse('Failed to fetch brewery data.', 'API_ERROR', $status_code);
        }
    }    

    public function getBreweryDetails($request) {
        $param = $request->get_params();
        $brewery_id = isset($param['id']) ? $param['id'] : null;
    
        // Ensure the brewery ID is provided
        if (empty($brewery_id)) {
            return $this->errorResponse('Please provide the brewery ID.');
        }
    
        // Build the API URL for fetching the brewery details by ID
        $url = 'https://api.openbrewerydb.org/v1/breweries/' . $brewery_id;
    
        $response = wp_remote_get($url);
        $body = wp_remote_retrieve_body($response);
        $status_code = wp_remote_retrieve_response_code($response);
    
        // Check if the response is successful
        if ($status_code == 200) {
            $brewery_details = json_decode($body, true);
    
            // Optionally, validate the brewery data if needed
            if ($brewery_details && isset($brewery_details['id'])) {
                return $this->successResponse('Brewery details fetched successfully.', $brewery_details);
            } else {
                return $this->errorResponse('Brewery not found.');
            }
        } else {
            return $this->errorResponse('Failed to fetch brewery data.', 'API_ERROR', $status_code);
        }
    }
    
    public function insertReview($request) {
        global $wpdb;
        $param = $request->get_params();
    
        // Debug incoming request data
        error_log('Request Params: ' . print_r($param, true));
    
        // Validate the parameters
        if (empty($param['brewery_id'])) {
            return $this->errorResponse('Please provide brewery ID.');
        }
    
        if (empty($param['rating']) || $param['rating'] < 1 || $param['rating'] > 5) {
            return $this->errorResponse('Rating must be between 1 and 5.');
        }
    
        if (empty($param['description'])) {
            return $this->errorResponse('Please provide a description.');
        }
    
        // Ensure user is logged in and has a valid user ID
        $this->isValidToken();
        $user_id = !empty($this->user_id) ? $this->user_id : null;
        if (empty($user_id)) {
            return $this->errorResponse('Unauthorized', 'Unauthorized', 401);
        }
    
        // Insert the review into the database
        $insert_result = $wpdb->insert(
            'review', // Table name
            array(
                'user_id' => $user_id,
                'brewery_id' => sanitize_text_field($param['brewery_id']), // Ensure brewery_id is treated as a string
                'rating' => intval($param['rating']), // Ensure rating is treated as an integer
                'description' => sanitize_textarea_field($param['description']), // Sanitize description
                'created_at' => current_time('mysql'),
            ),
            array('%d', '%s', '%d', '%s', '%s') // Data formats: integer, string, integer, string, string
        );
    
        // Check if the insert was successful
        if ($insert_result) {
            return $this->successResponse('Review added successfully.');
        } else {
            return $this->errorResponse('Failed to add review. Please try again.');
        }
    }    

    public function getBreweryReviews($request) {
        global $wpdb;
        $param = $request->get_params();
    
        // Validate brewery ID parameter
        if (empty($param['brewery_id'])) {
            return $this->errorResponse('Please provide brewery ID.');
        }
    
        // Fetch reviews from the review table for the specific brewery
        $reviews = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT r.id, r.user_id, r.brewery_id, r.rating, r.description, r.created_at
                 FROM review r
                 WHERE r.brewery_id = %d
                 ORDER BY r.created_at DESC",
                $param['brewery_id']
            )
        );
    
        if (empty($reviews)) {
            return $this->successResponse('No reviews yet. Add a review.', []);
        }
    
        // Enhance reviews with user metadata (user_name)
        foreach ($reviews as $key => $review) {
            $user_id = $review->user_id;
    
            // Meta query to fetch the user's name
            $user_name = $wpdb->get_var(
                $wpdb->prepare(
                    "SELECT meta_value
                     FROM {$wpdb->usermeta}
                     WHERE user_id = %d AND meta_key = 'name'",
                    $user_id
                )
            );
    
            // Set the user name in the review object
            $review->user_name = $user_name ?: 'Anonymous'; // Default to 'Anonymous' if no name is found
        }
    
        return $this->successResponse('Reviews retrieved successfully.', $reviews);
    }          

}           
$serverApi = new Custom_API();
add_filter('jwt_auth_token_before_dispatch', array( $serverApi, 'jwt_auth' ), 20, 2);
add_action('wp_error_added',  array($serverApi, 'errorResponse'), 99, 3);
?>