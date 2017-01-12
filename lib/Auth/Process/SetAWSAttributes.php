<?php
/**
 * Filter to add AWS IAM integration attributes
 *
 * This filter will set the following AWS-specific attributes required by IAM:
 * 
 *     https://aws.amazon.com/SAML/Attributes/Role
 *     Used by IAM to map allowed pairings of IAM role and
 *     federated identity provider.
 *     
 *     https://aws.amazon.com/SAML/Attributes/RoleSessionName
 *     Used by IAM to uniquely identify the federated user
 * 
 * It will also handle these AWS-specific optional attributes:
 * 
 *     https://aws.amazon.com/SAML/Attributes/SessionDuration
 *     Used by IAM to set the duration of the login session
 *
 * @author Evan King
 */
class sspmod_aws_Auth_Process_SetAWSAttributes extends SimpleSAML_Auth_ProcessingFilter {
    
    const ROLE_ATTRIBUTE = 'https://aws.amazon.com/SAML/Attributes/Role';
    const NAME_ATTRIBUTE = 'https://aws.amazon.com/SAML/Attributes/RoleSessionName';
    const DURATION_ATTRIBUTE = 'https://aws.amazon.com/SAML/Attributes/SessionDuration';

    /**
     * Name of existing attribute to expose in SAML as AWS RoleSessionName
     */
    private $uidAttribute = 'uid';

    /**
     * 12-digit id number of the aws account being connected
     */
    private $awsAccountId = null;

    /**
     * Name of the associated identity provider definition in IAM
     */
    private $iamProviderName = null;

    /**
     * Names of attributes containing role names/ids
     */
    private $roleAttributes = array('group');

    /**
     * Map of AWS role name => array of local role names/ids granting it
     */
    private $iamRoles = array();

    /**
     * Lifetime of the login session
     */
    private $sessionDurationSeconds = 3600; // 1 hour

    /**
     * Whether to set all matching roles (else set only the first match found)
     */
    private $matchAll = false;

    /**
     * Initialize this filter.
     *
     * @param array $config  Configuration information about this filter.
     * @param mixed $reserved  For future use.
     * @throws SimpleSAML_Error_Exception In case of invalid configuration.
     */
    public function __construct($config, $reserved) {
        parent::__construct($config, $reserved);

        assert('is_array($config)');
        
        // parse filter configuration
        foreach($config as $name => $value) {
            switch($name) {
                
                case 'attribute.uid': $this->uidAttribute = (string)$value; break;
                case 'attribute.role': $this->roleAttributes = $this->toArray($value); break;
                case 'session.duration': $this->sessionDurationSeconds = (int)$value; break;
                case 'aws.account': $this->awsAccountId = (string)$value; break;
                case 'iam.provider': $this->iamProviderName = (string)$value; break;
                case 'match.all': $this->matchAll = (bool)$value; break;
                
                case 'iam.roles':
                    foreach($value as $awsRole => $localValues) {
                        $this->iamRoles[$awsRole] = $this->toArray($localValues);
                    }
                    break;
                
                default:
                    throw new SimpleSAML_Error_Exception('Unknown flag : ' . var_export($value, true));
            }
        }
        
        if(!$this->awsAccountId) {
            throw new SimpleSAML_ErrorException("Config option 'aws.account' must be set");
        }
        
        if(!$this->iamProviderName) {
            throw new SimpleSAML_ErrorException("Config option 'iam.provider' must be set");
        }
    }

    /**
     * Apply the filter to add AWS attributes.
     *
     * @param array &$request The current request.
     * @throws SimpleSAML_Error_Exception In case of invalid configuration.
     */
    public function process(&$request) {
        assert('is_array($request)');
        assert('array_key_exists("Attributes", $request)');

        // get attributes from request
        $attributes =& $request['Attributes'];
        
        // set RoleSessionName
        $loginId = $attributes[$this->uidAttribute][0];
        if(!$loginId) {
            throw new SimpleSAML_Error_Exception(
                "No session name available (should have been in {$this->uidAttribute})"
            );
        }
        $attributes[self::NAME_ATTRIBUTE] = array($loginId);
        
        // set SessionDuration
        $attributes[self::DURATION_ATTRIBUTE] = array($this->sessionDurationSeconds);
        
        // get all local roles
        $allLocalRoles = array();
        foreach($this->roleAttributes as $attr) {
            $allLocalRoles += $this->toArray($attributes[$attr]);
        }
        
        // set Roles
        foreach($this->iamRoles as $iamRole => $localRoles) {
            if(array_intersect($allLocalRoles, $localRoles)) {
                $attributes[self::ROLE_ATTRIBUTE][] = $this->roleValue($iamRole);
                if(!$this->matchAll) break;
            }
        }
    }
    
    private function toArray($val) {
        return is_array($val) ? $val : array($val);
    }
    
    private function roleValue($name) {
        $acct = "arn:aws:iam::{$this->awsAccountId}";
        return "$acct:role/$name,$acct:saml-provider/{$this->iamProviderName}";
    }
}
