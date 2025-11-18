create table api_key_challenges_pool (
    site_key varchar not null,
    challenge_url varchar not null,
    created_at timestamptz not null default now(),
    constraint api_key_challenges_pool_pkey primary key (site_key, challenge_url),
    constraint api_key_challenges_pool_site_key_fkey foreign key (site_key) references api_key (site_key)
        on delete cascade,
    constraint api_key_challenges_pool_challenge_url_fkey foreign key (challenge_url) references challenge (url)
        on delete cascade
);
