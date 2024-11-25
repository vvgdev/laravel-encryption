<?php
/**
 * src/Traits/EncryptedAttribute.php.
 *
 */
namespace PHPCodersNp\DBEncryption\Traits;

use PHPCodersNp\DBEncryption\Builders\EncryptionEloquentBuilder;
use PHPCodersNp\DBEncryption\Encrypter;

trait EncryptedAttribute {

    public static $enableEncryption = true;

     /**
     * @param $key
     * @return bool
     */
    public function isEncryptable($key)
    {
        if(self::$enableEncryption){
            return in_array($key, $this->encryptable);
        }
        return false;
    }

    /**
     * @return mixed
     */
    public function getEncryptableAttributes()
    {
        return $this->encryptable;
    }

    public function getAttribute($key)
    {
      $value = parent::getAttribute($key);
      if ($this->isEncryptable($key) && (!is_null($value) && $value != ''))
      {
        try {
          $value = Encrypter::decrypt($value);
        } catch (\Exception $th) {}
      }
      return $value;
    }

    public function setAttribute($key, $value)
    {
      if ($this->isEncryptable($key) && (!is_null($value) && $value != ''))
      {
        try {
          $value = Encrypter::encrypt($value);
        } catch (\Exception $th) {}
      }
      return parent::setAttribute($key, $value);
    }

    public function attributesToArray()
    {
      $attributes = parent::attributesToArray();
      if ($attributes) {
        foreach ($attributes as $key => $value)
        {
          if ($this->isEncryptable($key) && (!is_null($value)) && $value != '')
          {
            $attributes[$key] = $value;
            try {
              $attributes[$key] = Encrypter::decrypt($value);
            } catch (\Exception $th) {}
          }
        }
      }
      return $attributes;
    }
    
    // Extend EncryptionEloquentBuilder
    public function newEloquentBuilder($query)
    {
        return new EncryptionEloquentBuilder($query);
    }

    public function decryptAttribute($value)
    {
      return (!is_null($value) && $value != '') ? Encrypter::decrypt($value) : $value;
    }

    public function encryptAttribute($value)
    {
      return (!is_null($value) && $value != '') ? Encrypter::encrypt($value) : $value;
    }
}
