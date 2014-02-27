<?php
/**
 * ConfigReader
 *
 * Author: Mark Troyer <disco@box.com>
 * Date Created: 24 February 2014
 *
 */

namespace StatusWolf\Config;

interface ConfigReader {
    function read($config_file);
    function understands($config_file);
}
