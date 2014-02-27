<?php
/**
 * ConfigServiceProvider
 *
 * Describe your class here
 *
 * Author: Mark Troyer <disco@box.com>
 * Date Created: 27 February 2014
 *
 */

namespace StatusWolf\Config;

use Silex\Application;
use Silex\ServiceProviderInterface;

class ConfigServiceProvider implements ServiceProviderInterface {

    private $_config_file;
    private $_config_reader;

    public function __construct($filename, ConfigReader $reader = null) {
        $this->_config_file = $filename;
        $this->_config_reader = $reader ?: new JsonConfigReader();
    }

    public function register(Application $sw) {
        $config = $this->read_config_file();
        $this->merge_config($sw, $config);
    }

    public function boot(Application $sw) {}

    public function merge_config(Application $sw, array $config) {
        foreach ($config as $key => $value) {
            if (isset($sw[$key]) && is_array($value)) {
                $sw[$key] = $this->merge_config_recursive($sw[$key], $value);
            } else {
                $sw[$key] = $value;
            }
        }
    }

    public function merge_config_recursive(array $current_value, array $new_value) {
        foreach ($new_value as $key => $value) {
            if (is_array($value) && isset($current_value[$key])) {
                $current_value[$key] = $this->merge_config_recursive($current_value[$key], $value);
            } else {
                $current_value[$key] = $value;
            }
        }
        return $current_value;
    }

    public function read_config_file() {
        if (!$this->_config_file) {
            throw new \RuntimeException('A valid config file name must be provided.');
        }

        if (!file_exists($this->_config_file)) {
            throw new \InvalidArgumentException(
                sprintf("Config file %s does not exist.", $this->_config_file)
            );
        }

        if ($this->_config_reader->understands($this->_config_file)) {
            return $this->_config_reader->read($this->_config_file);
        }

        throw new \InvalidArgumentException(
            sprintf("Config file %s is invalid.", $this->_config_file)
        );
    }

}
