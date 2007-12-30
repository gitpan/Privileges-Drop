use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
    module_name        => 'Privileges::Drop',
    license            => 'perl',
    dist_author        => 'Troels Liebe Bentsen <troels@infopro.dk>',
    dist_version_from  => 'lib/Privileges/Drop.pm',
    create_makefile_pl => 'traditional',
    create_readme      => 1,
    build_requires => {
        'Test::More' => 0,
    },
    add_to_cleanup => [ 
        'Privileges-Drop-*',
        'blib',
    ],
);

$builder->create_build_script();
