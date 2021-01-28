<?php

namespace Laranoia\Guards;

use Illuminate\Support\ServiceProvider;

class GuardsServiceProvider extends ServiceProvider
{

    public function boot()
    {
        $this->publishes([
            __DIR__ . '/../config/guards.php' => config_path('guards.php'),
        ], 'config');

        \Auth::extend('x509', function ($app, $name, array $config) {
            return $app->make(\Laranoia\Guards\Contracts\X509::class, [
                'events' => $app['events'],
                'provider' => \Auth::createUserProvider($config['provider']),
                'request' => $app['request']
            ]);
        });
    }

    public function register()
    {
        $this->mergeConfigFrom(
            $this->app->configPath('guards.php'),
            'guards'
        );

        $this->app->bind(\Laranoia\Guards\Contracts\X509::class, $this->app->config['guards.bindings.x509']);
    }
}