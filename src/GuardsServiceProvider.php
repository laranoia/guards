<?php

namespace Laranoia\Guards;

use Illuminate\Support\ServiceProvider;
use Laranoia\Guards\Guards\X509;

class GuardsServiceProvider extends ServiceProvider{

    public function boot(){
        \Auth::extend('x509', function ($app, $name, array $config) {
            return new X509($app['events'], \Auth::createUserProvider($config['provider']), $app['request']);
        });
    }
}