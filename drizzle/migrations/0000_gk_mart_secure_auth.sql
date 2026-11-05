CREATE TYPE public.app_role AS ENUM ('Admin','Shop Owner','Manager','Cashier','Inventory Staff','Accountant');

CREATE TABLE public.profiles (
  id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  name text NOT NULL DEFAULT '',
  email text NOT NULL DEFAULT '',
  mobile text NOT NULL DEFAULT '',
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, UPDATE ON public.profiles TO authenticated;
GRANT ALL ON public.profiles TO service_role;
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

CREATE TABLE public.user_roles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  role public.app_role NOT NULL,
  UNIQUE (user_id, role)
);
GRANT SELECT ON public.user_roles TO authenticated;
GRANT ALL ON public.user_roles TO service_role;
ALTER TABLE public.user_roles ENABLE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION public.has_role(_user_id uuid, _role public.app_role)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM public.user_roles WHERE user_id = _user_id AND role = _role)
$$;

CREATE OR REPLACE FUNCTION public.is_active_staff(_user_id uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM public.profiles WHERE id = _user_id AND active)
$$;

CREATE OR REPLACE FUNCTION public.is_shop_admin(_user_id uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT public.is_active_staff(_user_id) AND (public.has_role(_user_id,'Admin') OR public.has_role(_user_id,'Shop Owner'))
$$;

CREATE POLICY "profiles_read_self_or_admin" ON public.profiles FOR SELECT TO authenticated
  USING (auth.uid() = id OR public.is_shop_admin(auth.uid()));
CREATE POLICY "profiles_update_admin" ON public.profiles FOR UPDATE TO authenticated
  USING (public.is_shop_admin(auth.uid())) WITH CHECK (public.is_shop_admin(auth.uid()));
CREATE POLICY "roles_read_self_or_admin" ON public.user_roles FOR SELECT TO authenticated
  USING (auth.uid() = user_id OR public.is_shop_admin(auth.uid()));

CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE first_user boolean;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext('gk_mart_first_user'));
  SELECT NOT EXISTS (SELECT 1 FROM public.profiles) INTO first_user;
  INSERT INTO public.profiles (id, name, email)
  VALUES (NEW.id, left(COALESCE(NULLIF(NEW.raw_user_meta_data->>'name',''), split_part(NEW.email,'@',1)), 100), COALESCE(NEW.email,''));
  INSERT INTO public.user_roles (user_id, role)
  VALUES (NEW.id, CASE WHEN first_user THEN 'Admin'::public.app_role ELSE 'Cashier'::public.app_role END);
  RETURN NEW;
END;
$$;
CREATE TRIGGER on_auth_user_created AFTER INSERT ON auth.users
FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

CREATE TABLE public.shop_records (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  entity text NOT NULL,
  local_id bigint NOT NULL,
  payload jsonb NOT NULL,
  deleted boolean NOT NULL DEFAULT false,
  updated_at timestamptz NOT NULL DEFAULT now(),
  updated_by uuid,
  UNIQUE (entity, local_id)
);
CREATE INDEX shop_records_updated_at_idx ON public.shop_records (updated_at);
GRANT SELECT, INSERT, UPDATE ON public.shop_records TO authenticated;
GRANT ALL ON public.shop_records TO service_role;
ALTER TABLE public.shop_records ENABLE ROW LEVEL SECURITY;
CREATE POLICY "shop_records_active_read" ON public.shop_records FOR SELECT TO authenticated
  USING (public.is_active_staff(auth.uid()) AND entity <> 'employees');
CREATE POLICY "shop_records_active_insert" ON public.shop_records FOR INSERT TO authenticated
  WITH CHECK (public.is_active_staff(auth.uid()) AND updated_by = auth.uid() AND entity <> 'employees');
CREATE POLICY "shop_records_active_update" ON public.shop_records FOR UPDATE TO authenticated
  USING (public.is_active_staff(auth.uid()) AND entity <> 'employees')
  WITH CHECK (public.is_active_staff(auth.uid()) AND updated_by = auth.uid() AND entity <> 'employees');

CREATE OR REPLACE FUNCTION public.touch_updated_at()
RETURNS trigger LANGUAGE plpgsql SET search_path = public AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END; $$;
CREATE TRIGGER shop_records_touch BEFORE UPDATE ON public.shop_records FOR EACH ROW EXECUTE FUNCTION public.touch_updated_at();
CREATE TRIGGER profiles_touch BEFORE UPDATE ON public.profiles FOR EACH ROW EXECUTE FUNCTION public.touch_updated_at();

REVOKE ALL ON FUNCTION public.handle_new_user() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.touch_updated_at() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.has_role(uuid, public.app_role) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.is_active_staff(uuid) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.is_shop_admin(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.has_role(uuid, public.app_role), public.is_active_staff(uuid), public.is_shop_admin(uuid) TO authenticated;