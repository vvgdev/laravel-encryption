<?php

/**
 * src/Builders/EncryptionEloquentBuilder.php.
 *
 */

namespace PHPCodersNp\DBEncryption\Builders;

use Illuminate\Database\Eloquent\Builder;
use RuntimeException;

class EncryptionEloquentBuilder extends Builder
{
  protected $salt;
  public function __construct($query)
  {
    parent::__construct($query);
    
    // Get app key for encryption key
    $key = config('laravelDatabaseEncryption.encrypt_key');
    if (empty($key)) {
      throw new RuntimeException('Encryption key not set in configuration.');
    }

    $salt = substr(hash('sha256', $key), 0, 32); // Ensure 32 bytes for AES-256 and 16 bytes for AES-128
    if (strlen($salt) !== 32) {
      throw new RuntimeException('Invalid encryption key length.');
    }

    $this->salt = $salt;
  }
  public function whereEncrypted($param1, $param2, $param3 = null)
  {
    $filter = new \stdClass();
    $filter->field = $param1;
    $filter->operation = isset($param3) ? $param2 : '=';
    $filter->value = isset($param3) ? $param3 : $param2;

    // Check if the field contains a table alias (i.e., dot notation)
    if (strpos($param1, '.') !== false) {
      $parts = explode('.', $param1);
      return self::whereRaw(
        "CONVERT(
                AES_DECRYPT(
                    FROM_BASE64(SUBSTRING(FROM_BASE64(`{$parts[0]}`.`{$parts[1]}`), 17)),
                    '{$this->salt}',
                    SUBSTRING(FROM_BASE64(`{$parts[0]}`.`{$parts[1]}`), 1, 16)
                ) USING utf8mb4
            ) {$filter->operation} ?",
        [$filter->value]
      );
    } else {
      return self::whereRaw(
        "CONVERT(
                AES_DECRYPT(
                    FROM_BASE64(SUBSTRING(FROM_BASE64(`{$filter->field}`), 17)),
                    '{$this->salt}',
                    SUBSTRING(FROM_BASE64(`{$filter->field}`), 1, 16)
                ) USING utf8mb4
            ) {$filter->operation} ?",
        [$filter->value]
      );
    }
  }

  public function orWhereEncrypted($param1, $param2, $param3 = null)
  {
    $filter = new \stdClass();
    $filter->field = $param1;
    $filter->operation = isset($param3) ? $param2 : '=';
    $filter->value = isset($param3) ? $param3 : $param2;

    // Check if the field contains a table alias (i.e., dot notation)
    if (strpos($param1, '.') !== false) {
      $parts = explode('.', $param1);
      return self::orWhereRaw(
        "CONVERT(
                AES_DECRYPT(
                    FROM_BASE64(SUBSTRING(FROM_BASE64(`{$parts[0]}`.`{$parts[1]}`), 17)),
                    '{$this->salt}',
                    SUBSTRING(FROM_BASE64(`{$parts[0]}`.`{$parts[1]}`), 1, 16)
                ) USING utf8mb4
            ) {$filter->operation} ?",
        [$filter->value]
      );
    } else {
      return self::orWhereRaw(
        "CONVERT(
                AES_DECRYPT(
                    FROM_BASE64(SUBSTRING(FROM_BASE64(`{$filter->field}`), 17)),
                    '{$this->salt}',
                    SUBSTRING(FROM_BASE64(`{$filter->field}`), 1, 16)
                ) USING utf8mb4
            ) {$filter->operation} ?",
        [$filter->value]
      );
    }
  }

  public function orderByEncrypted($column, $direction = 'asc')
  {
    // Normalize the direction to avoid SQL injection risks
    $direction = strtolower($direction) === 'desc' ? 'DESC' : 'ASC';

    if (strpos($column, '.') !== false) {
      $parts = explode('.', $column);
      return self::orderByRaw(
        "CONVERT(
                AES_DECRYPT(
                    FROM_BASE64(SUBSTRING(FROM_BASE64(`{$parts[0]}`.`{$parts[1]}`), 17)),
                    '{$this->salt}',
                    SUBSTRING(FROM_BASE64(`{$parts[0]}`.`{$parts[1]}`), 1, 16)
                ) USING utf8mb4
            ) {$direction}"
      );
    } else {
      return self::orderByRaw(
        "CONVERT(
                AES_DECRYPT(
                    FROM_BASE64(SUBSTRING(FROM_BASE64(`{$column}`), 17)),
                    '{$this->salt}',
                    SUBSTRING(FROM_BASE64(`{$column}`), 1, 16)
                ) USING utf8mb4
            ) {$direction}"
      );
    }
  }


  public function selectEncrypted(array $columns)
  {
    $selects = [];

    foreach ($columns as $column) {
      // Split column and alias (if any)
      $parts = preg_split('/\s+as\s+|\s+AS\s+/', $column);
      $columnNameAlias = trim($parts[0]);

      // Check if the column includes a table alias
      if (strpos($columnNameAlias, '.') !== false) {
        $columnNameParts = explode('.', $columnNameAlias);
        $tableName = $columnNameParts[0];
        $columnName = $columnNameParts[1];
      } else {
        $tableName = null;
        $columnName = $columnNameAlias;
      }

      // Determine alias name
      $columnAlias = count($parts) === 2 ? trim($parts[1]) : $columnName;

      // Construct decrypted selection statement
      if ($tableName) {
        $selects[] = "CONVERT(
                AES_DECRYPT(
                    FROM_BASE64(SUBSTRING(FROM_BASE64(`{$tableName}`.`{$columnName}`), 17)),
                    '{$this->salt}',
                    SUBSTRING(FROM_BASE64(`{$tableName}`.`{$columnName}`), 1, 16)
                ) USING utf8mb4
            ) AS `{$columnAlias}`";
      } else {
        $selects[] = "CONVERT(
                AES_DECRYPT(
                    FROM_BASE64(SUBSTRING(FROM_BASE64(`{$columnName}`), 17)),
                    '{$this->salt}',
                    SUBSTRING(FROM_BASE64(`{$columnName}`), 1, 16)
                ) USING utf8mb4
            ) AS `{$columnAlias}`";
      }
    }

    return self::selectRaw(implode(', ', $selects));
  }


  public function concatEncrypted($columns, $defaultSeparator = ' ')
  {

    $parts = preg_split('/\s+as\s+|\s+AS\s+/', $columns);

    if (count($parts) == 2) {
      $columnAlias = trim($parts[1]);
      $singleParts = array_map('trim', explode(',', $parts[0]));

      if (count($singleParts) == 3) {
        [$columnNameAlias1, $separator, $columnNameAlias2] = $singleParts;

        $separator = trim($separator, '"\'');
        $separator = $separator ?: $defaultSeparator;

        [$tableName1, $columnName1] = explode('.', $columnNameAlias1);
        $encryptedColumn1 = "CONVERT(
          AES_DECRYPT(
              FROM_BASE64(SUBSTRING(FROM_BASE64(`{$tableName1}`.`{$columnName1}`), 17)),
              '{$this->salt}',
              SUBSTRING(FROM_BASE64(`{$tableName1}`.`{$columnName1}`), 1, 16)
          ) USING utf8mb4)";


        [$tableName2, $columnName2] = explode('.', $columnNameAlias2);
        $encryptedColumn2 = "CONVERT(
          AES_DECRYPT(
              FROM_BASE64(SUBSTRING(FROM_BASE64(`{$tableName2}`.`{$columnName2}`), 17)),
              '{$this->salt}',
              SUBSTRING(FROM_BASE64(`{$tableName2}`.`{$columnName2}`), 1, 16)
          ) USING utf8mb4)";

        return self::selectRaw("CONCAT_WS('{$separator}', {$encryptedColumn1}, {$encryptedColumn2}) AS `{$columnAlias}`");
      }
    }
  }
}
