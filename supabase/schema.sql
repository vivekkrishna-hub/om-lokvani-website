create extension if not exists pgcrypto;

create table if not exists public.services (
 id uuid primary key default gen_random_uuid(),
 slug text unique not null,
 name_hi text not null,
 name_en text not null,
 fee_paise integer not null default 0 check (fee_paise >= 0),
 active boolean not null default true,
 form_schema jsonb not null default '{}'::jsonb,
 required_documents jsonb not null default '[]'::jsonb,
 created_at timestamptz not null default now(),
 updated_at timestamptz not null default now()
);

create table if not exists public.applications (
 id uuid primary key default gen_random_uuid(),
 application_id text unique not null,
 service_id uuid references public.services(id),
 applicant_name text not null,
 mobile text not null,
 email text,
 address text,
 form_data jsonb not null default '{}'::jsonb,
 status text not null default 'NEW',
 fee_paise integer not null default 0,
 payment_status text not null default 'PENDING',
 payment_order_id text,
 payment_id text,
 payment_signature text,
 created_at timestamptz not null default now(),
 updated_at timestamptz not null default now()
);

create table if not exists public.documents (
 id uuid primary key default gen_random_uuid(),
 application_id uuid not null references public.applications(id) on delete cascade,
 storage_path text not null,
 original_name text not null,
 mime_type text not null,
 size_bytes bigint not null,
 created_at timestamptz not null default now()
);

create table if not exists public.inquiries (
 id uuid primary key default gen_random_uuid(),
 inquiry_id text unique not null,
 name text not null,
 mobile text not null,
 service_id uuid references public.services(id),
 message text not null,
 status text not null default 'NEW',
 created_at timestamptz not null default now(),
 updated_at timestamptz not null default now()
);


create table if not exists public.admin_users (
 id uuid primary key default gen_random_uuid(),
 admin_id text not null,
 mobile text unique not null,
 password_hash text,
 active boolean not null default true,
 created_at timestamptz not null default now(),
 updated_at timestamptz not null default now()
);

create table if not exists public.audit_logs (
 id bigserial primary key,
 actor text not null,
 action text not null,
 entity_type text,
 entity_id text,
 ip text,
 created_at timestamptz not null default now()
);

create table if not exists public.payment_webhook_events (
 id bigserial primary key,
 event_id text unique not null,
 event_type text not null,
 order_id text,
 payment_id text,
 created_at timestamptz not null default now()
);

insert into storage.buckets (id,name,public)
values ('private-documents','private-documents',false)
on conflict (id) do nothing;

create index if not exists applications_application_id_idx on public.applications(application_id);
create index if not exists applications_created_at_idx on public.applications(created_at desc);
create index if not exists documents_application_id_idx on public.documents(application_id);
create index if not exists inquiries_inquiry_id_idx on public.inquiries(inquiry_id);
create index if not exists inquiries_created_at_idx on public.inquiries(created_at desc);
create unique index if not exists applications_payment_id_unique_idx on public.applications(payment_id) where payment_id is not null;
create index if not exists payment_webhook_events_created_at_idx on public.payment_webhook_events(created_at desc);

-- Backend-only Data API access: the browser never receives the secret key.
-- Keep RLS enabled even though the Express backend uses the Supabase secret/service key.
alter table public.services enable row level security;
alter table public.applications enable row level security;
alter table public.documents enable row level security;
alter table public.inquiries enable row level security;
alter table public.audit_logs enable row level security;
alter table public.payment_webhook_events enable row level security;
alter table public.admin_users enable row level security;

revoke all on public.services from anon, authenticated;
revoke all on public.applications from anon, authenticated;
revoke all on public.documents from anon, authenticated;
revoke all on public.inquiries from anon, authenticated;
revoke all on public.audit_logs from anon, authenticated;
revoke all on public.payment_webhook_events from anon, authenticated;
revoke all on public.admin_users from anon, authenticated;

-- Seed the live service-fee panel. Fees are in paise.
insert into public.services (slug,name_hi,name_en,fee_paise,required_documents) values
('aadhaar','आधार कार्ड सेवाएँ','Aadhaar Services',5000,'["आधार कार्ड","मोबाइल नंबर/अन्य आवश्यक जानकारी"]'::jsonb),
('income','आय प्रमाण पत्र','Income Certificate',5000,'["आधार कार्ड","फोटो","अन्य आवश्यक दस्तावेज"]'::jsonb),
('caste','जाति प्रमाण पत्र','Caste Certificate',5000,'["आधार कार्ड","जाति संबंधी प्रमाण","अन्य दस्तावेज"]'::jsonb),
('domicile','निवास प्रमाण पत्र','Domicile Certificate',5000,'["आधार कार्ड","पता संबंधी प्रमाण"]'::jsonb),
('pan','PAN Card नया आवेदन','New PAN Card',15000,'["आधार कार्ड","फोटो","हस्ताक्षर"]'::jsonb),
('pan-correction','PAN Card संशोधन','PAN Correction',15000,'["PAN","आधार/समर्थन दस्तावेज"]'::jsonb),
('pmmvy','प्रधानमंत्री मातृ वंदना योजना','PMMVY',10000,'["आधार","बैंक विवरण","योजना संबंधी दस्तावेज"]'::jsonb),
('scholarship','छात्रवृत्ति आवेदन','Scholarship',10000,'["आधार","मार्कशीट","बैंक पासबुक","अन्य दस्तावेज"]'::jsonb),
('other','अन्य ऑनलाइन आवेदन','Other Online Services',10000,'["सेवा के अनुसार आवश्यक दस्तावेज"]'::jsonb)
on conflict (slug) do update set name_hi=excluded.name_hi,name_en=excluded.name_en,required_documents=excluded.required_documents;
