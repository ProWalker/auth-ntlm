<?php

class property_exception extends Exception
{
    public function __construct($property, $message = "", $code = 0, Throwable $previous = null)
    {
        $message = "Свойство {$property} не найдено!";

        parent::__construct($message, $code, $previous);
    }

}