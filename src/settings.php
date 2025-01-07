<?php
return [
    'settings' => [
        'displayErrorDetails' => true, // set to false in production
        'addContentLengthHeader' => false, // Allow the web server to send the content-length header

        // Renderer settings
        'renderer' => [
            'template_path' => __DIR__ . '/../templates/',
        ],

        // Monolog settings
        'logger' => [
            'name' => 'slim-app',
            'path' => isset($_ENV['docker']) ? 'php://stdout' : __DIR__ . '/../logs/app.log',
            'level' => \Monolog\Logger::DEBUG,
        ],

        // Dropbox settings
        'dropbox' => [
          'provider' => 'dropbox',
          'client_id' => getenv('DROPBOX_ID') ?: 'vgij09edeilbrtm',
          'client_secret' => getenv('DROPBOX_SECRET'),
          'redirect_uri' => (getenv('REDIRECT_BASEURI') ?: 'https://cloud.scummvm.org').'/dropbox',
          'grant_type' => '',
        ],

        // Box settings
        'box' => [
          'provider' => 'box',
          'client_id' => getenv('BOX_ID') ?: 'ep9cz17to1wakzqbq2a5jn5u01b0omxw',
          'client_secret' => getenv('BOX_SECRET'),
          'redirect_uri' => (getenv('REDIRECT_BASEURI') ?: 'https://cloud.scummvm.org').'/box',
        ],

        // Google Drive settings
        'gdrive' => [
          'provider' => 'gdrive',
          'client_id' => getenv('GOOGLE_DRIVE_ID') ?: '201747806507-m6mclc7ijtp0v1fbj2qqehrdoh3uhofp.apps.googleusercontent.com',
          'client_secret' => getenv('GOOGLE_DRIVE_SECRET'),
          'redirect_uri' => (getenv('REDIRECT_BASEURI') ?: 'https://cloud.scummvm.org').'/gdrive',
        ],

        // Onedrive settings
        'onedrive' => [
          'provider' => 'onedrive',
          'client_id' => getenv('ONEDRIVE_ID') ?: '12c88b6d-3037-4c0c-9076-cc4205cfb1d0',
          'client_secret' => getenv('ONEDRIVE_SECRET'),
          'redirect_uri' =>  (getenv('REDIRECT_BASEURI') ?: 'https://cloud.scummvm.org').'/onedrive',
        ],
    ],
];
